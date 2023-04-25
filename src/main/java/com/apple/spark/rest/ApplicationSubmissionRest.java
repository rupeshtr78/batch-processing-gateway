/*
 *
 * This source file is part of the Batch Processing Gateway open source project
 *
 * Copyright 2022 Apple Inc. and the Batch Processing Gateway project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.apple.spark.rest;

import static com.apple.spark.core.ApplicationSubmissionHelper.*;
import static com.apple.spark.core.BatchSchedulerConstants.YUNIKORN_ROOT_QUEUE;
import static com.apple.spark.core.BatchSchedulerConstants.YUNIKORN_SCHEDULER;
import static com.apple.spark.core.Constants.*;
import static com.apple.spark.core.MonitoringConstants.ENABLE_METRICS_CONF;

import com.apple.spark.AppConfig;
import com.apple.spark.api.DeleteSubmissionResponse;
import com.apple.spark.api.GetDriverInfoResponse;
import com.apple.spark.api.GetMySubmissionsResponse;
import com.apple.spark.api.GetSubmissionStatusResponse;
import com.apple.spark.api.SubmissionSummary;
import com.apple.spark.api.SubmitApplicationRequest;
import com.apple.spark.api.SubmitApplicationResponse;
import com.apple.spark.appleinternal.AppleKerberosUtil;
import com.apple.spark.appleinternal.AppleNotaryUtil;
import com.apple.spark.core.*;
import com.apple.spark.crd.VirtualSparkClusterSpec;
import com.apple.spark.operator.*;
import com.apple.spark.security.User;
import com.apple.spark.util.ConfigUtil;
import com.apple.spark.util.CustomSerDe;
import com.apple.spark.util.DateTimeUtils;
import com.apple.spark.util.ExceptionUtils;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.annotation.ExceptionMetered;
import com.codahale.metrics.annotation.Timed;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.dropwizard.auth.Auth;
import io.fabric8.kubernetes.api.model.*;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.fabric8.kubernetes.client.dsl.base.CustomResourceDefinitionContext;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.annotation.security.PermitAll;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@PermitAll
@Path(SPARK_API)
@Produces(MediaType.APPLICATION_JSON)
public class ApplicationSubmissionRest extends RestBase {

  private static final Logger logger = LoggerFactory.getLogger(ApplicationSubmissionRest.class);
  private final LogDao logDao;
  private final MetricRegistry registry;

  private final long statusCacheExpireMillis;
  private final LoadingCache<String, GetSubmissionStatusResponseCacheValue>
      statusCache; // a cache of submission status using submission ID as key

  public ApplicationSubmissionRest(AppConfig appConfig, MeterRegistry meterRegistry) {
    super(appConfig, meterRegistry);
    this.registry = SharedMetricRegistries.getDefault();

    String dbConnectionString = null;
    String dbUser = null;
    String dbPassword = null;
    String dbName = null;

    if (appConfig.getDbStorageSOPS() != null) {
      dbConnectionString = appConfig.getDbStorageSOPS().getConnectionString();
      dbUser = appConfig.getDbStorageSOPS().getUser();
      dbPassword = appConfig.getDbStorageSOPS().getPasswordDecodedValue();
      dbName = appConfig.getDbStorageSOPS().getDbName();
    }

    this.logDao = new LogDao(dbConnectionString, dbUser, dbPassword, dbName, meterRegistry);

    if (appConfig.getStatusCacheExpireMillis() != null) {
      statusCacheExpireMillis = appConfig.getStatusCacheExpireMillis();
    } else {
      statusCacheExpireMillis = DEFAULT_STATUS_CACHE_EXPIRE_MILLIS;
    }
    logger.info("Creating status cache with expire millis: {}", statusCacheExpireMillis);

    CacheLoader<String, GetSubmissionStatusResponseCacheValue> loader;
    loader =
        new CacheLoader<String, GetSubmissionStatusResponseCacheValue>() {
          @Override
          public GetSubmissionStatusResponseCacheValue load(String submissionId) {
            requestCounters.increment(STATUS_CACHE_LOAD);
            VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
            try {
              GetSubmissionStatusResponse response =
                  getStatusImplWithoutCache(submissionId, sparkCluster);
              return new GetSubmissionStatusResponseCacheValue(response);
            } catch (Throwable ex) {
              requestCounters.increment(
                  STATUS_CACHE_LOAD_FAILURE, Tag.of("exception", ex.getClass().getSimpleName()));
              logger.warn(
                  String.format("Failed to load status from Kubernetes for %s", submissionId), ex);
              if (ExceptionUtils.isTooManyRequest(ex)) {
                GetSubmissionStatusResponse response = new GetSubmissionStatusResponse();
                response.setApplicationState(UNKNOWN_STATE);
                response.setApplicationErrorMessage(ExceptionUtils.getExceptionNameAndMessage(ex));
                return new GetSubmissionStatusResponseCacheValue(response);
              } else {
                return new GetSubmissionStatusResponseCacheValue(ex);
              }
            }
          }
        };

    statusCache =
        CacheBuilder.newBuilder()
            .expireAfterWrite(statusCacheExpireMillis, TimeUnit.MILLISECONDS)
            .build(loader);
  }

  @POST
  @Timed
  @Operation(
      summary = "Submit a Spark application",
      description =
          "To submit a job, prepare a job payload in the request body either"
              + " in JSON or YAML format.",
      tags = {"Submission"})
  @ApiResponse(
      responseCode = "200",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = SubmitApplicationResponse.class)))
  @ApiResponse(
      responseCode = "400",
      description = "Bad request due to wrong format or invalid values")
  @ApiResponse(responseCode = "415", description = "Unsupported content type")
  @ApiResponse(responseCode = "500", description = "Internal server error")
  @Consumes({MediaType.APPLICATION_JSON, "text/yaml", MediaType.WILDCARD})
  @ExceptionMetered(
      name = "WebApplicationException",
      absolute = true,
      cause = WebApplicationException.class)
  public SubmitApplicationResponse submitApplication(
      @RequestBody(
              description =
                  "All the specification of the job, including necessary artifacts, versions,"
                      + " driver and executor specs",
              required = true,
              content = @Content(schema = @Schema(implementation = SubmitApplicationRequest.class)))
          String requestBody,
      @Parameter(
              description =
                  "options: application/json, text/yaml, or leave it empty for API to figure out")
          @HeaderParam("content-type")
          String contentType,
      @Parameter(description = "Client version", hidden = true)
          @DefaultValue("none")
          @HeaderParam("Client-Version")
          String clientVersion,
      @Parameter(
              description =
                  "DAG user from Airflow."
                      + "This can be used when the username used for auth needs to be overwritten",
              hidden = true)
          @DefaultValue("dagUser")
          @QueryParam("dagUser")
          String dagUser,
      @Parameter(hidden = true) @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "submitApplication",
        clientVersion);

    return timerMetrics.record(
        () -> submitApplicationImpl(requestBody, contentType, user, dagUser),
        REQUEST_LATENCY_METRIC_NAME,
        Tag.of("name", "submit_application"),
        Tag.of("user", getUserTagValue(user)),
        Tag.of("proxy_user", getProxyUser(user.getName(), dagUser)));
  }

  private SubmitApplicationResponse submitApplicationImpl(
      String requestBody, String contentType, User user, String dagUser) {
    SubmitApplicationRequest request =
        ApplicationSubmissionHelper.parseSubmitRequest(requestBody, contentType);

    // some sanity check on some basic requirements for a request
    validateSubmissionRequest(request);

    // choose Spark cluster to submit the job to
    VirtualSparkClusterSpec sparkCluster =
        SparkClusterHelper.chooseSparkCluster(appConfig, request, user.getName());

    String sparkVersionTagValue =
        request.getSparkVersion() != null ? request.getSparkVersion() : "";

    String submissionId =
        ApplicationSubmissionHelper.generateSubmissionId(
            sparkCluster.getId(), request.getSubmissionIdSuffix());
    logger.info("Creating application submission: {}", submissionId);

    // Use the DAG user in case the user is a system account from Airflow jobs
    String proxyUser = getProxyUser(user.getName(), dagUser);

    // Java / Python
    String type = getType(request.getType(), request.getMainClass());
    String sparkVersion = request.getSparkVersion();

    String queue = SparkClusterHelper.getQueue(appConfig, request, user.getName());
    String parentQueue = SparkClusterHelper.getParentQueue(queue);
    String queueTagValue = queue == null ? "" : queue;

    // Reject GPU jobs submitted to non-GPU queues
    validateGpuRequest(request, queue);

    // Populate Prometheus monitoring configs into the request
    if (request.getSparkConf() != null
        && Boolean.parseBoolean(request.getSparkConf().get(ENABLE_METRICS_CONF))) {
      logger.info("Detected enable_metrics=true, the Spark job JMX metrics will be exported");
      populatePrometheusMonitoring(request);
      populatePrometheusAnnotations(request);
    }

    // the Spark spec to be submitted to Spark cluster
    SparkApplicationSpec.Builder specBuilder =
        new SparkApplicationSpec.Builder()
            .withMode(SparkConstants.CLUSTER_MODE)
            .withOriginalUser(user.getName())
            .withType(type)
            .withProxyUser(proxyUser)
            .withSparkVersion(sparkVersion)
            .withMainClass(request.getMainClass())
            .withMainApplicationFile(request.getMainApplicationFile())
            .withDriver(getDriverSpec(request, appConfig, parentQueue, sparkCluster))
            .withExecutor(getExecutorSpec(request, appConfig, parentQueue, sparkCluster))
            .withImage(getImage(getAppConfig(), request, type, sparkVersion, proxyUser))
            .withArguments(request.getArguments())
            .withImagePullPolicy(request.getImagePullPolicy())
            .withRestartPolicy(request.getRestartPolicy())
            .withVolumes(request.getVolumes())
            .withDeps(request.getDeps())
            .withMonitoringSpec(request.getMonitoring())
            .withPythonVersion(request.getPythonVersion())
            .withTimeToLiveSeconds(sparkCluster.getTtlSeconds())
            .extendSparkConf(
                getSparkConf(submissionId, request, appConfig.getDefaultSparkConf(), sparkCluster))
            .withSparkUIConfiguration(getSparkUIConfiguration(submissionId, sparkCluster))
            .extendVolumes(getVolumes(request, sparkCluster))
            .extendVolumeMounts(getVolumeMounts(request, sparkCluster));

    // only set scheduler if it's YuniKorn
    String batchScheduler = sparkCluster.getBatchScheduler();
    if (batchScheduler != null) {
      if (batchScheduler.equals(YUNIKORN_SCHEDULER)) {
        specBuilder.withBatchScheduler(YUNIKORN_SCHEDULER);
        specBuilder.withBatchSchedulerOptions(getYuniKornSchedulerConfig(queue));
        logger.info("Setting queue of submission {} to {}", submissionId, queue);
      } else {
        logger.info(
            "batchScheduler {} is not supported. Revert to using the default-scheduler",
            batchScheduler);
      }
    }

    SparkApplicationSpec sparkSpec = specBuilder.build();

    // Set environment variables
    ApplicationSubmissionHelper.populateEnv(sparkSpec, request, sparkCluster);

    if (sparkSpec.getSparkConf() != null) {
      String disableProxyUserConfValue = sparkSpec.getSparkConf().get(Constants.DISABLE_PROXY_USER);
      if (disableProxyUserConfValue != null && disableProxyUserConfValue.equalsIgnoreCase("true")) {
        sparkSpec.setProxyUser(null);
      }
    }

    requestCounters.increment(
        REQUEST_METRIC_NAME,
        Tag.of("name", "submit_application"),
        Tag.of("user", user.getName()),
        Tag.of("proxy_user", proxyUser),
        Tag.of("spark_version", sparkVersionTagValue),
        Tag.of("spark_cluster", sparkCluster.getId()),
        Tag.of("queue", queueTagValue));

    // Setting a default Spark conf to support spark query listener
    // rdar://98086206 (Hot fix: Enable spark listener for the latest Spark 3.2 image)
    // This should only be set when default spark images are used
    // TODO: clean this up and make this configurable in Skate config
    if (request.getImage() == null || request.getImage().isEmpty()) {
      applyQueryListenerSparkConf(sparkSpec);
    }

    logDao.logApplicationSubmission(submissionId, proxyUser, request);
    SubmitApplicationResponse response =
        submitSparkCRD(
            sparkCluster, submissionId, sparkSpec, request, queue, parentQueue, proxyUser);
    return response;
  }

  private SubmitApplicationResponse submitSparkCRD(
      VirtualSparkClusterSpec sparkCluster,
      String submissionId,
      SparkApplicationSpec sparkSpec,
      SubmitApplicationRequest request,
      String queue,
      String parentQueue,
      String proxyUser) {
    com.codahale.metrics.Timer timer =
        registry.timer(this.getClass().getSimpleName() + ".submitApplication.k8s-time");

    try (KubernetesClient client = KubernetesHelper.getK8sClient(sparkCluster);
        com.codahale.metrics.Timer.Context context = timer.time()) {
      SparkApplication sparkApplication = new SparkApplication();
      sparkApplication.setApiVersion(SparkConstants.SPARK_OPERATOR_API_VERSION);
      sparkApplication.setKind(SparkConstants.SPARK_APPLICATION_KIND);
      sparkApplication.getMetadata().setName(submissionId);
      sparkApplication.getMetadata().setNamespace(sparkCluster.getSparkApplicationNamespace());

      if (sparkApplication.getMetadata().getLabels() == null) {
        sparkApplication.getMetadata().setLabels(new HashMap<>());
      }
      if (proxyUser != null) {
        sparkApplication.getMetadata().getLabels().put(PROXY_USER_LABEL, proxyUser);
      }
      if (request.getApplicationName() != null) {
        String applicationNameLabelValue =
            KubernetesHelper.normalizeLabelValue(request.getApplicationName());
        sparkApplication
            .getMetadata()
            .getLabels()
            .put(APPLICATION_NAME_LABEL, applicationNameLabelValue);
      }

      sparkApplication
          .getMetadata()
          .getLabels()
          .put(QUEUE_LABEL, YUNIKORN_ROOT_QUEUE + "." + queue);

      long maxRunningMillis = DEFAULT_MAX_RUNNING_MILLIS;
      // check max running time from request
      if (request.getSparkConf() != null) {
        String confValue = request.getSparkConf().get(CONFIG_MAX_RUNNING_MILLIS);
        if (confValue != null && !confValue.isEmpty()) {
          try {
            maxRunningMillis = Long.parseLong(confValue);
          } catch (Throwable ex) {
            throw new WebApplicationException(
                String.format(
                    "Invalid value for config %s: %s", CONFIG_MAX_RUNNING_MILLIS, confValue),
                Response.Status.BAD_REQUEST);
          }
          // make sure max running time not exceed the configured value for the queue
          long maxRunningMillisForQueue = getMaxRunningMillisForQueue(parentQueue);
          if (maxRunningMillisForQueue < maxRunningMillis) {
            throw new WebApplicationException(
                String.format(
                    "maxRunningMillis %s is too large than allowed %s for queue %s",
                    maxRunningMillis, maxRunningMillisForQueue, queue),
                Response.Status.BAD_REQUEST);
          }
        }
      }
      sparkApplication
          .getMetadata()
          .getLabels()
          .put(MAX_RUNNING_MILLIS_LABEL, String.valueOf(maxRunningMillis));

      if (request.getSpotInstance()) {
        long spotTimeoutMillis = getMaxRunningMillisForQueue(parentQueue);
        // check spot timeout setting from request
        if (request.getSparkConf() != null) {
          String confValue = request.getSpotTimeoutMillis();
          if (confValue != null && !confValue.isEmpty()) {
            try {
              spotTimeoutMillis = Long.parseLong(confValue);
            } catch (Throwable ex) {
              throw new WebApplicationException(
                  String.format(
                      "Invalid value for config %s: %s", Constants.SPOT_TIMEOUT_LABEL, confValue),
                  Response.Status.BAD_REQUEST);
            }
            // make sure spot timeout not exceed the configured value for the queue
            long maxRunningMillisForQueue = getMaxRunningMillisForQueue(parentQueue);
            if (maxRunningMillisForQueue < spotTimeoutMillis) {
              throw new WebApplicationException(
                  String.format(
                      "spotTimeoutMillis %s is too large than allowed %s for queue %s",
                      spotTimeoutMillis, maxRunningMillisForQueue, queue),
                  Response.Status.BAD_REQUEST);
            }
          }
        }

        sparkApplication
            .getMetadata()
            .getLabels()
            .put(SPOT_INSTANCE_LABEL, String.valueOf(request.getSpotInstance()));

        sparkApplication
            .getMetadata()
            .getLabels()
            .put(SPOT_TIMEOUT_LABEL, String.valueOf(spotTimeoutMillis));
      }

      try {
        String sparkSpecJson = CustomSerDe.sparkSpecToNonSensitiveJson(sparkSpec);
        logger.info("Spark Spec (non-sensitive info): {}", sparkSpecJson);
      } catch (Throwable ex) {
        logger.warn("Failed to serialize SparkApplicationSpec and mask sensitive info", ex);
      }

      // The following line is for Apple only, and should be excluded from Open Source Upstream
      AppleKerberosUtil.enableKerberosSupport(
          sparkSpec, request, appConfig, proxyUser, timerMetrics);

      AppConfig.QueueConfig queueConfig = null;
      if (appConfig.getQueues() != null) {
        Optional<AppConfig.QueueConfig> optional =
            appConfig.getQueues().stream()
                .filter(t -> t.getName() != null && t.getName().equals(queue))
                .findFirst();
        if (optional.isPresent()) {
          queueConfig = optional.get();
        }
      }


      // Notary token support
      try {

        String notaryAppIdEnvVar = AppleNotaryUtil.BPG_NOTARY_APP_ID;

          if (!AppleNotaryUtil.checkNotaryApplication(notaryAppIdEnvVar)) {
            logger.warn("Token not generated not a valid notary application");
          } else {
            AppleNotaryUtil.enableNotaryEnvironmentVariable(sparkApplication,sparkSpec);
            logger.info("Notary token generated");
          }
      } catch (Exception ex) {
        logger.warn("Failed to create Notary Token", ex);
      }


      AwsCredentialSparkConfigProvider.addAwsCredentialSparkConfig(sparkSpec, queueConfig);
      CustomResourceDefinitionContext crdContext = KubernetesHelper.getSparkApplicationCrdContext();

      sparkApplication.setSpec(sparkSpec);

      MixedOperation<SparkApplication, SparkApplicationResourceList, Resource<SparkApplication>>
          sparkApplicationClient =
              client.resources(SparkApplication.class, SparkApplicationResourceList.class);

      sparkApplicationClient.create(sparkApplication);

      SubmitApplicationResponse response = new SubmitApplicationResponse();
      response.setSubmissionId(submissionId);
      context.stop();
      return response;
    }
  }

  @DELETE()
  @Path("{submissionId}")
  @Timed
  @Operation(
      summary = "Delete Spark application by submission ID",
      description =
          "After a job is submitted, you can use the submission ID returned to delete the job.",
      tags = {"Deletion"})
  @ApiResponse(
      responseCode = "200",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = DeleteSubmissionResponse.class)))
  @ApiResponse(
      responseCode = "400",
      description = "Bad request due to invalid submission ID or other issues")
  @ApiResponse(responseCode = "500", description = "Internal server error")
  public DeleteSubmissionResponse deleteSubmission(
      @Parameter(description = "The submission ID returned by submission API")
          @PathParam("submissionId")
          String submissionId,
      @Parameter(hidden = true) @DefaultValue("none") @HeaderParam("Client-Version")
          String clientVersion,
      @Parameter(hidden = true) @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "deleteSubmission",
        clientVersion);
    requestCounters.increment(
        REQUEST_METRIC_NAME, Tag.of("name", "delete_submission"), Tag.of("user", user.getName()));

    VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
    com.codahale.metrics.Timer timer =
        registry.timer(this.getClass().getSimpleName() + ".deleteSubmission.k8s-time");
    try (KubernetesClient client = KubernetesHelper.getK8sClient(sparkCluster);
        com.codahale.metrics.Timer.Context context = timer.time()) {
      CustomResourceDefinitionContext crdContext = KubernetesHelper.getSparkApplicationCrdContext();
      MixedOperation<SparkApplication, SparkApplicationResourceList, Resource<SparkApplication>>
          sparkApplicationClient =
              client.resources(SparkApplication.class, SparkApplicationResourceList.class);

      sparkApplicationClient
          .inNamespace(sparkCluster.getSparkApplicationNamespace())
          .withName(submissionId)
          .delete();

      context.stop();
      return new DeleteSubmissionResponse();
    }
  }

  @GET()
  @Path("{submissionId}/spec")
  @Timed
  @ExceptionMetered(
      name = "WebApplicationException",
      absolute = true,
      cause = WebApplicationException.class)
  @Operation(
      summary = "Get Spark application spec by submission ID.",
      description = "Return the detailed spec of the Spark job.",
      tags = {"Examination"})
  @ApiResponse(
      responseCode = "200",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = SparkApplicationSpec.class)))
  @ApiResponse(
      responseCode = "400",
      description = "Bad request due to invalid submission ID or other issues")
  @ApiResponse(responseCode = "500", description = "Internal server error")
  public SparkApplicationSpec getSparkSpec(
      @PathParam("submissionId") String submissionId,
      @Parameter(hidden = true) @DefaultValue("none") @HeaderParam("Client-Version")
          String clientVersion,
      @Parameter(hidden = true) @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "getSparkSpec",
        clientVersion);
    requestCounters.increment(
        REQUEST_METRIC_NAME, Tag.of("name", "get_spec"), Tag.of("user", user.getName()));
    SparkApplication sparkApplication = getSparkApplicationResource(submissionId);
    SparkApplicationSpec sparkApplicationSpec = removeEnvFromSpec(sparkApplication.getSpec());
    return sparkApplicationSpec;
  }

  @GET()
  @Path("{submissionId}/status")
  @Timed
  @ExceptionMetered(
      name = "WebApplicationException",
      absolute = true,
      cause = WebApplicationException.class)
  @Operation(
      summary = "Get Spark application status by submission ID.",
      description = "May return an empty object when the Spark application is not be started yet.",
      tags = {"Examination"})
  public GetSubmissionStatusResponse getStatus(
      @PathParam("submissionId") String submissionId,
      @Parameter(hidden = true) @DefaultValue("none") @HeaderParam("Client-Version")
          String clientVersion,
      @Parameter(hidden = true) @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "getStatus",
        clientVersion);
    return timerMetrics.record(
        () -> getStatusImpl(submissionId, user),
        REQUEST_LATENCY_METRIC_NAME,
        Tag.of("name", "get_status"),
        Tag.of("user", getUserTagValue(user)));
  }

  private GetSubmissionStatusResponse getStatusImpl(String submissionId, User user) {
    requestCounters.increment(
        REQUEST_METRIC_NAME, Tag.of("name", "get_status"), Tag.of("user", user.getName()));

    GetSubmissionStatusResponseCacheValue cacheValue;
    try {
      cacheValue = statusCache.get(submissionId);
    } catch (ExecutionException ex) {
      requestCounters.increment(
          STATUS_CACHE_GET_FAILURE, Tag.of("exception", ex.getClass().getSimpleName()));
      logger.warn(String.format("Failed to get status from cache for %s", submissionId), ex);
      VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
      return getStatusImplWithoutCache(submissionId, sparkCluster);
    }

    if (cacheValue == null) {
      logger.warn("Got null status cache value for {}", submissionId);
      VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
      return getStatusImplWithoutCache(submissionId, sparkCluster);
    }

    long cacheElapsedTime = System.currentTimeMillis() - cacheValue.getCreatedTimeMillis();
    // The cache library should make sure the cached value refreshed after expiration.
    // Just in case the cache library has issue and does not refresh,
    // we check it again here and force fetching status from Kubernetes if necessary.
    if (cacheElapsedTime > statusCacheExpireMillis * 2) {
      logger.warn(
          "Got expired status cache value ({} millis) for {}", cacheElapsedTime, submissionId);
      VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
      return getStatusImplWithoutCache(submissionId, sparkCluster);
    }

    if (cacheValue.getResponse() == null) {
      if (cacheValue.getException() != null) {
        Throwable cachedException = cacheValue.getException();
        if (cachedException instanceof WebApplicationException) {
          throw (WebApplicationException) cachedException;
        }
        throw new WebApplicationException(
            String.format(
                "Failed to get status: %s",
                ExceptionUtils.getExceptionNameAndMessage(cacheValue.getException())),
            Response.Status.INTERNAL_SERVER_ERROR);
      } else {
        throw new WebApplicationException(
            "Failed to get status (got null status from cache)",
            Response.Status.INTERNAL_SERVER_ERROR);
      }
    }

    return cacheValue.getResponse();
  }

  private GetSubmissionStatusResponse getStatusImplWithoutCache(
      String submissionId, VirtualSparkClusterSpec sparkCluster) {
    com.codahale.metrics.Timer timer =
        registry.timer(this.getClass().getSimpleName() + ".getStatus.k8s-time");
    try (KubernetesClient client = KubernetesHelper.getK8sClient(sparkCluster);
        com.codahale.metrics.Timer.Context context = timer.time()) {
      MixedOperation<SparkApplication, SparkApplicationResourceList, Resource<SparkApplication>>
          sparkApplicationClient =
              client.resources(SparkApplication.class, SparkApplicationResourceList.class);

      SparkApplication sparkApplication =
          sparkApplicationClient
              .inNamespace(sparkCluster.getSparkApplicationNamespace())
              .withName(submissionId)
              .get();

      context.stop();
      if (sparkApplication == null) {
        throw new WebApplicationException(
            String.format("Application submission %s not found", submissionId),
            Response.Status.NOT_FOUND);
      }
      GetSubmissionStatusResponse response = new GetSubmissionStatusResponse();
      response.copyFrom(sparkApplication);

      if (!StringUtils.isEmpty(sparkCluster.getSparkUIUrl())) {
        if (SparkConstants.RUNNING_STATE.equalsIgnoreCase(response.getApplicationState())
            || SparkConstants.SPOT_TIMEOUT_STATE.equalsIgnoreCase(response.getApplicationState())) {
          String url = ConfigUtil.getSparkUIUrl(sparkCluster, submissionId);
          response.setSparkUIUrl(url);
        }

        if ((SparkConstants.COMPLETED_STATE.equalsIgnoreCase(response.getApplicationState())
                || SparkConstants.FAILED_STATE.equalsIgnoreCase(response.getApplicationState()))
            && appConfig.getSparkHistoryDns() != null
            && response.getSparkApplicationId() != null) {
          String url =
              ConfigUtil.getSparkHistoryUrl(
                  appConfig.getSparkHistoryDns(), response.getSparkApplicationId());
          response.setSparkUIUrl(url);
        }
      }

      // add more information regarding max running time
      String extraMessage = "";
      if (sparkApplication.getMetadata().getLabels() != null) {
        String maxRunningMillisLabel =
            sparkApplication.getMetadata().getLabels().get(MAX_RUNNING_MILLIS_LABEL);
        if (maxRunningMillisLabel != null && !maxRunningMillisLabel.isEmpty()) {
          try {
            long maxRunningMillis = Long.parseLong(maxRunningMillisLabel);
            if (maxRunningMillis > DEFAULT_MAX_RUNNING_MILLIS) {
              extraMessage =
                  String.format(
                      "(warning: application is configured with custom max running time: %s millis,"
                          + " but might be still killed in certain situations like maintenance)",
                      maxRunningMillis);
            }
            if (FAILED_STATE.equals(response.getApplicationState())) {
              if (response.getTerminationTime() != null && response.getCreationTime() != null) {
                long runningMillis = response.getTerminationTime() - response.getCreationTime();
                // check whether running time is close to max running time allowed,
                // if they are close, add extra information in response
                if (runningMillis >= maxRunningMillis - TimeUnit.MINUTES.toMillis(2)) {
                  extraMessage = "(application might be killed because of running too long)";
                }
              }
            }
          } catch (Throwable ex) {
            logger.warn(
                String.format("Failed to check max running mills for %s", submissionId), ex);
          }
        }
      }

      // add more information regarding spot timeout
      String extraSpotTimeoutMessage = "";
      if (SPOT_TIMEOUT.equals(response.getApplicationState())) {
        String spotTimeoutMillisLabel =
            sparkApplication.getMetadata().getLabels().get(Constants.SPOT_TIMEOUT_LABEL);
        long spotTimeoutMillisSetting = Long.parseLong(spotTimeoutMillisLabel);
        extraSpotTimeoutMessage =
            String.format(
                "(warning: application is configured with spot timeout: %s millis,"
                    + " and running time has exceed it, please consider kill it and retry "
                    + "on On-Demand instances by setting spot-instance to False )",
                spotTimeoutMillisSetting);
      }

      if (extraMessage != null && !extraMessage.isEmpty()) {
        String consolidatedMessage = response.getApplicationErrorMessage();
        if (consolidatedMessage == null) {
          consolidatedMessage = "";
        } else {
          consolidatedMessage = consolidatedMessage + " ";
        }
        consolidatedMessage = consolidatedMessage + extraMessage;

        if (extraSpotTimeoutMessage != null && !extraSpotTimeoutMessage.isEmpty()) {
          consolidatedMessage = consolidatedMessage + extraSpotTimeoutMessage;
        }

        response.setApplicationErrorMessage(consolidatedMessage);
      }
      return response;
    }
  }

  @GET()
  @Path("{submissionId}/driver")
  @Timed
  @ExceptionMetered(
      name = "WebApplicationException",
      absolute = true,
      cause = WebApplicationException.class)
  @Operation(
      summary = "Get Spark application driver information.",
      description = "May return an empty object when the Spark application has not started yet.",
      tags = {"Examination"})
  @ApiResponse(
      responseCode = "200",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = GetDriverInfoResponse.class)))
  @ApiResponse(
      responseCode = "400",
      description = "Bad request due to invalid submission ID or other issues")
  @ApiResponse(responseCode = "500", description = "Internal server error")
  public GetDriverInfoResponse getDriverInfo(
      @PathParam("submissionId") String submissionId,
      @Parameter(hidden = true) @DefaultValue("none") @HeaderParam("Client-Version")
          String clientVersion,
      @Parameter(hidden = true) @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "getDriverInfo",
        clientVersion);
    requestCounters.increment(
        REQUEST_METRIC_NAME, Tag.of("name", "get_driver"), Tag.of("user", user.getName()));

    VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
    SparkApplication sparkApplicationResource = getSparkApplicationResource(submissionId);
    if (sparkApplicationResource.getStatus() == null
        || sparkApplicationResource.getStatus().getDriverInfo() == null) {
      return new GetDriverInfoResponse();
    }
    DriverInfo driverInfo = sparkApplicationResource.getStatus().getDriverInfo();
    if (driverInfo == null || driverInfo.getPodName() == null) {
      return new GetDriverInfoResponse();
    }

    Pod pod = getPod(driverInfo.getPodName(), sparkCluster);
    if (pod == null) {
      return new GetDriverInfoResponse();
    }
    PodStatus podStatus = pod.getStatus();
    if (podStatus == null) {
      return new GetDriverInfoResponse();
    }
    String startTimeStr = podStatus.getStartTime();
    Long startTimeMillis = DateTimeUtils.parseOrNull(startTimeStr);
    GetDriverInfoResponse response = new GetDriverInfoResponse();
    response.setPodName(driverInfo.getPodName());
    response.setStartTime(startTimeMillis);

    return response;
  }

  @GET()
  @Path("{submissionId}/describe")
  @Timed
  @ExceptionMetered(
      name = "WebApplicationException",
      absolute = true,
      cause = WebApplicationException.class)
  @Operation(
      summary = "Get spark application spec and related events as a text stream.",
      description = "May return an empty stream when the Spark application has not started yet.",
      tags = {"Examination"})
  @ApiResponse(responseCode = "200", content = @Content(mediaType = "application/octet-stream"))
  @ApiResponse(
      responseCode = "400",
      description = "Bad request due to invalid submission ID or other issues")
  @ApiResponse(responseCode = "500", description = "Internal server error")
  public Response describe(
      @PathParam("submissionId") String submissionId,
      @DefaultValue("none") @HeaderParam("Client-Version") String clientVersion,
      @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}", user.getName(), "describe", clientVersion);
    requestCounters.increment(
        REQUEST_METRIC_NAME,
        Tag.of("name", "describe_application"),
        Tag.of("user", user.getName()));

    final SparkApplication sparkApplicationResource = getSparkApplicationResource(submissionId);
    SparkApplicationSpec sparkApplicationSpec =
        removeEnvFromSpec(sparkApplicationResource.getSpec());

    ObjectMapper objectMapper =
        new ObjectMapper(
            new YAMLFactory()
                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES));
    String yaml = "";
    try {
      yaml = objectMapper.writeValueAsString(sparkApplicationSpec);
    } catch (JsonProcessingException e) {
      ExceptionUtils.meterJsonProcessingException();
      logger.warn("Failed to serialize spark application spec to yaml", e);
    }
    final String sparkApplicationSpecYaml = yaml;

    VirtualSparkClusterSpec sparkCluster = getSparkCluster(submissionId);
    List<Event> sparkApplicationEvents = getEvents(sparkCluster, submissionId);

    String driverName = String.format("%s-driver", submissionId);
    List<Event> driverEvents = getEvents(sparkCluster, driverName);

    return Response.ok(
            new RestStreamingOutput() {
              final byte[] buffer = new byte[8196]; // Should make this configurable in the future

              @Override
              public void write(OutputStream outputStream)
                  throws IOException, WebApplicationException {
                logger.info("Streaming log for submission {}", submissionId);
                try {
                  writeLine(outputStream, "--- Spark Spec ---");
                  writeLine(outputStream, sparkApplicationSpecYaml);
                  outputStream.flush();

                  writeLine(outputStream, "--- Spark Application Events ---");
                  for (Event event : sparkApplicationEvents) {
                    writeLine(
                        outputStream,
                        String.format(
                            "%s %s %s",
                            event.getEventTime().getTime(), event.getReason(), event.getMessage()));
                  }
                  outputStream.flush();

                  writeLine(outputStream, "--- Spark Driver Events ---");
                  for (Event event : driverEvents) {
                    writeLine(
                        outputStream,
                        String.format(
                            "%s %s %s",
                            event.getEventTime().getTime(), event.getReason(), event.getMessage()));
                  }
                  outputStream.flush();

                  logger.info("Finished streaming log for submission {}", submissionId);
                } catch (Throwable ex) {
                  logger.warn(
                      String.format(
                          "Hit exception when streaming log for submission %s", submissionId),
                      ex);
                  ExceptionUtils.meterException();
                }
              }
            })
        .build();
  }

  @GET
  @Path("mySubmissions")
  @Hidden
  @Timed
  @Operation(summary = "Get submissions for current user")
  public GetMySubmissionsResponse getSubmissions(
      @DefaultValue("none") @HeaderParam("Client-Version") String clientVersion, @Auth User user) {
    logger.info(
        "LogClientInfo: user {}, {}, Client-Version {}",
        user.getName(),
        "getSubmissions",
        clientVersion);
    requestCounters.increment(
        REQUEST_METRIC_NAME, Tag.of("name", "my_submissions"), Tag.of("user", user.getName()));

    checkRateForListSubmissions("mySubmissions");

    List<SubmissionSummary> submissionList = new ArrayList<>();
    for (VirtualSparkClusterSpec sparkCluster : getSparkClusters()) {
      SparkApplicationResourceList list =
          getSparkApplicationResourcesByUser(sparkCluster, user.getName());
      List<SparkApplication> sparkApplicationResources = list.getItems();
      if (sparkApplicationResources != null) {
        for (SparkApplication sparkApplication : sparkApplicationResources) {
          SubmissionSummary submission = new SubmissionSummary();
          submission.copyFrom(sparkApplication, sparkCluster, getAppConfig());
          submissionList.add(submission);
        }
      }
    }
    GetMySubmissionsResponse response = new GetMySubmissionsResponse();
    response.setSubmissions(submissionList);
    return response;
  }

  protected List<Event> getEvents(VirtualSparkClusterSpec sparkCluster, String objectName) {
    Map<String, String> fields = new HashMap<>();
    fields.put("involvedObject.name", objectName);
    com.codahale.metrics.Timer timer =
        registry.timer(this.getClass().getSimpleName() + ".getEvents.k8s-time");
    try (KubernetesClient client = KubernetesHelper.getK8sClient(sparkCluster);
        com.codahale.metrics.Timer.Context context = timer.time()) {

      EventList eventList =
          client
              .v1()
              .events()
              .inNamespace(sparkCluster.getSparkApplicationNamespace())
              .withFields(fields)
              .list();

      context.stop();
      if (eventList == null) {
        return Collections.EMPTY_LIST;
      }
      return eventList.getItems();
    }
  }

  /**
   * Remove env variables from spec to avoid leaking sensitive information
   *
   * @param sparkApplicationSpec full application spec (will be modified)
   * @return modified application spec
   */
  private SparkApplicationSpec removeEnvFromSpec(SparkApplicationSpec sparkApplicationSpec) {
    try {
      if (sparkApplicationSpec.getDriver().getEnv() != null) {
        sparkApplicationSpec.getDriver().setEnv(null);
      }
      if (sparkApplicationSpec.getExecutor().getEnv() != null) {
        sparkApplicationSpec.getExecutor().setEnv(null);
      }
    } catch (Exception e) {
      logger.warn("Failed to remove env variables from spec {}", e);
    }
    return sparkApplicationSpec;
  }

  private String getUserTagValue(User user) {
    if (user != null && user.getName() != null) {
      return user.getName();
    } else {
      return "";
    }
  }

  private long getMaxRunningMillisForQueue(String queue) {
    Optional<AppConfig.QueueConfig> queueConfigOptional =
        appConfig.getQueues().stream().filter(t -> t.getName().equals(queue)).findFirst();
    if (queueConfigOptional.isPresent()) {
      AppConfig.QueueConfig queueConfig = queueConfigOptional.get();
      if (queueConfig != null && queueConfig.getMaxRunningMillis() != null) {
        return queueConfig.getMaxRunningMillis();
      }
    }
    return DEFAULT_MAX_RUNNING_MILLIS;
  }

  /**
   * Ensure the submission request satisfies certain requirements. If executor spec is present in
   * request, the number of executors shouldn't exceed the limit. If executor spec is present as
   * `spark.executor.instances` param in Spark conf, the number of executors shouldn't exceed the
   * limit.
   *
   * @param request submission request
   */
  private void validateSubmissionRequest(SubmitApplicationRequest request) {
    if (request.getExecutor() != null) {
      Integer instances = request.getExecutor().getInstances();
      if (instances != null) {
        if (instances > MAX_EXECUTOR_INSTANCES) {
          throw new WebApplicationException(
              String.format(
                  "Executor instances (%s) exceeds limit %s)", instances, MAX_EXECUTOR_INSTANCES),
              Response.Status.BAD_REQUEST);
        }
      }
    }
    if (request.getSparkConf() != null) {
      String configValueStr =
          request.getSparkConf().get(SparkConstants.SPARK_CONF_EXECUTOR_INSTANCES);
      if (configValueStr != null) {
        int instances;
        try {
          instances = Integer.parseInt(configValueStr);
        } catch (Throwable ex) {
          throw new WebApplicationException(
              String.format(
                  "Invalid value (%s) for Spark config: %s)",
                  configValueStr, SparkConstants.SPARK_CONF_EXECUTOR_INSTANCES),
              Response.Status.BAD_REQUEST);
        }
        if (instances > MAX_EXECUTOR_INSTANCES) {
          throw new WebApplicationException(
              String.format(
                  "Executor instances in Spark config (%s) exceeds limit %s)",
                  instances, MAX_EXECUTOR_INSTANCES),
              Response.Status.BAD_REQUEST);
        }
      }
    }
  }

  private void validateGpuRequest(SubmitApplicationRequest request, String queue) {
    if (request.getExecutor().getGpu() != null) {
      if (!appConfig.getQueueConfigs().containsKey(queue)
          || !appConfig.getQueueConfigs().get(queue).getSupportGpu()) {
        String errMsg = String.format("Queue %s doesn't support GPU", queue);
        logger.error(errMsg);
        throw new WebApplicationException(errMsg);
      }
    }
  }
}
