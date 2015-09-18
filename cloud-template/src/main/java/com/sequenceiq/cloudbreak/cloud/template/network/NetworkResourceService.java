package com.sequenceiq.cloudbreak.cloud.template.network;

import static com.sequenceiq.cloudbreak.cloud.scheduler.PollGroup.CANCELLED;
import static java.util.Arrays.asList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.sequenceiq.cloudbreak.cloud.event.context.AuthenticatedContext;
import com.sequenceiq.cloudbreak.cloud.event.context.CloudContext;
import com.sequenceiq.cloudbreak.cloud.event.context.ResourceBuilderContext;
import com.sequenceiq.cloudbreak.cloud.model.CloudResource;
import com.sequenceiq.cloudbreak.cloud.model.CloudResourceStatus;
import com.sequenceiq.cloudbreak.cloud.model.Network;
import com.sequenceiq.cloudbreak.cloud.model.Security;
import com.sequenceiq.cloudbreak.cloud.notification.PersistenceNotifier;
import com.sequenceiq.cloudbreak.cloud.scheduler.PollGroup;
import com.sequenceiq.cloudbreak.cloud.scheduler.SyncPollingScheduler;
import com.sequenceiq.cloudbreak.cloud.store.InMemoryStateStore;
import com.sequenceiq.cloudbreak.cloud.task.PollTask;
import com.sequenceiq.cloudbreak.cloud.task.PollTaskFactory;
import com.sequenceiq.cloudbreak.cloud.template.NetworkResourceBuilder;
import com.sequenceiq.cloudbreak.cloud.template.init.ResourceBuilders;
import com.sequenceiq.cloudbreak.domain.ResourceType;

@Service
public class NetworkResourceService {

    @Inject
    private ResourceBuilders resourceBuilders;
    @Inject
    private SyncPollingScheduler<List<CloudResourceStatus>> syncPollingScheduler;
    @Inject
    private PollTaskFactory statusCheckFactory;
    @Inject
    private PersistenceNotifier resourceNotifier;

    public List<CloudResourceStatus> buildResources(ResourceBuilderContext context,
            AuthenticatedContext auth, Network network, Security security) throws Exception {
        CloudContext cloudContext = auth.getCloudContext();
        List<CloudResourceStatus> results = new ArrayList<>();
        for (NetworkResourceBuilder builder : resourceBuilders.network(cloudContext.getPlatform())) {
            PollGroup pollGroup = InMemoryStateStore.get(auth.getCloudContext().getStackId());
            if (pollGroup != null && CANCELLED.equals(pollGroup)) {
                break;
            }
            CloudResource buildableResource = builder.create(context, auth, network, security);
            createResource(auth, buildableResource);
            CloudResource resource = builder.build(context, auth, network, security, buildableResource);
            PollTask<List<CloudResourceStatus>> task = statusCheckFactory.newPollResourceTask(builder, auth, asList(resource), context, true);
            List<CloudResourceStatus> pollerResult = syncPollingScheduler.schedule(task);
            results.addAll(pollerResult);
        }
        return results;
    }

    public List<CloudResourceStatus> deleteResources(ResourceBuilderContext context,
            AuthenticatedContext auth, List<CloudResource> resources, boolean cancellable) throws Exception {
        CloudContext cloudContext = auth.getCloudContext();
        List<CloudResourceStatus> results = new ArrayList<>();
        List<NetworkResourceBuilder> builderChain = resourceBuilders.network(cloudContext.getPlatform());
        for (int i = builderChain.size() - 1; i >= 0; i--) {
            NetworkResourceBuilder builder = builderChain.get(i);
            List<CloudResource> specificResources = getResources(resources, builder.resourceType());
            for (CloudResource resource : specificResources) {
                CloudResource deletedResource = builder.delete(context, auth, resource);
                if (deletedResource != null) {
                    PollTask<List<CloudResourceStatus>> task = statusCheckFactory.newPollResourceTask(
                            builder, auth, asList(deletedResource), context, cancellable);
                    List<CloudResourceStatus> pollerResult = syncPollingScheduler.schedule(task);
                    results.addAll(pollerResult);
                }
                resourceNotifier.notifyDeletion(resource, cloudContext).await();
            }
        }
        return results;
    }

    public List<CloudResourceStatus> update(ResourceBuilderContext context, AuthenticatedContext auth,
            Network network, Security security, List<CloudResource> networkResources) throws Exception {
        List<CloudResourceStatus> results = new ArrayList<>();
        CloudContext cloudContext = auth.getCloudContext();
        for (NetworkResourceBuilder builder : resourceBuilders.network(cloudContext.getPlatform())) {
            CloudResource resource = getResources(networkResources, builder.resourceType()).get(0);
            CloudResourceStatus status = builder.update(context, auth, network, security, resource);
            if (status != null) {
                PollTask<List<CloudResourceStatus>> task = statusCheckFactory.newPollResourceTask(
                        builder, auth, asList(status.getCloudResource()), context, true);
                List<CloudResourceStatus> pollerResult = syncPollingScheduler.schedule(task);
                results.addAll(pollerResult);
            }
        }
        return results;
    }

    public List<CloudResource> getNetworkResources(String platform, List<CloudResource> resources) {
        List<ResourceType> types = new ArrayList<>();
        for (NetworkResourceBuilder builder : resourceBuilders.network(platform)) {
            types.add(builder.resourceType());
        }
        return getResources(resources, types);
    }

    protected CloudResource createResource(AuthenticatedContext auth, CloudResource buildableResource) throws Exception {
        resourceNotifier.notifyAllocation(buildableResource, auth.getCloudContext()).await();
        return buildableResource;
    }

    private List<CloudResource> getResources(List<CloudResource> resources, ResourceType type) {
        return getResources(resources, Arrays.asList(type));
    }

    private List<CloudResource> getResources(List<CloudResource> resources, List<ResourceType> types) {
        List<CloudResource> filtered = new ArrayList<>();
        for (CloudResource resource : resources) {
            if (types.contains(resource.getType())) {
                filtered.add(resource);
            }
        }
        return filtered;
    }
}