package com.sequenceiq.cloudbreak.converter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.stereotype.Component;

import com.sequenceiq.cloudbreak.api.model.ClusterResponse;
import com.sequenceiq.cloudbreak.api.model.FailurePolicyJson;
import com.sequenceiq.cloudbreak.api.model.ImageJson;
import com.sequenceiq.cloudbreak.api.model.InstanceGroupJson;
import com.sequenceiq.cloudbreak.api.model.OrchestratorResponse;
import com.sequenceiq.cloudbreak.api.model.StackResponse;
import com.sequenceiq.cloudbreak.cloud.model.Image;
import com.sequenceiq.cloudbreak.core.CloudbreakImageNotFoundException;
import com.sequenceiq.cloudbreak.domain.InstanceGroup;
import com.sequenceiq.cloudbreak.domain.Stack;
import com.sequenceiq.cloudbreak.service.image.ImageService;

@Component
public class StackToJsonConverter extends AbstractConversionServiceAwareConverter<Stack, StackResponse> {
    private static final Logger LOGGER = LoggerFactory.getLogger(StackToJsonConverter.class);

    @Inject
    private ConversionService conversionService;

    @Inject
    private ImageService imageService;

    @Override
    public StackResponse convert(Stack source) {
        StackResponse stackJson = new StackResponse();
        try {
            Image image = imageService.getImage(source.getId());
            stackJson.setImage(getConversionService().convert(image, ImageJson.class));
        } catch (CloudbreakImageNotFoundException exc) {
            LOGGER.info(exc.getMessage());
        }
        stackJson.setName(source.getName());
        stackJson.setOwner(source.getOwner());
        stackJson.setAccount(source.getAccount());
        stackJson.setPublicInAccount(source.isPublicInAccount());
        stackJson.setId(source.getId());
        if (source.getCredential() == null) {
            stackJson.setCloudPlatform(null);
            stackJson.setCredentialId(null);
        } else {
            stackJson.setCloudPlatform(source.cloudPlatform());
            stackJson.setCredentialId(source.getCredential().getId());
        }
        stackJson.setStatus(source.getStatus());
        stackJson.setStatusReason(source.getStatusReason());
        stackJson.setRegion(source.getRegion());
        stackJson.setAvailabilityZone(source.getAvailabilityZone());
        stackJson.setOnFailureAction(source.getOnFailureActionAction());
        if (source.getSecurityGroup() != null) {
            stackJson.setSecurityGroupId(source.getSecurityGroup().getId());
        }
        List<InstanceGroupJson> templateGroups = new ArrayList<>();
        templateGroups.addAll(convertInstanceGroups(source.getInstanceGroups()));
        stackJson.setInstanceGroups(templateGroups);
        if (source.getCluster() != null) {
            stackJson.setCluster(getConversionService().convert(source.getCluster(), ClusterResponse.class));
        } else {
            stackJson.setCluster(new ClusterResponse());
        }
        if (source.getFailurePolicy() != null) {
            stackJson.setFailurePolicy(getConversionService().convert(source.getFailurePolicy(), FailurePolicyJson.class));
        }
        if (source.getNetwork() == null) {
            stackJson.setNetworkId(null);
        } else {
            stackJson.setNetworkId(source.getNetwork().getId());
        }
        stackJson.setRelocateDocker(source.getRelocateDocker());
        stackJson.setParameters(source.getParameters());
        stackJson.setPlatformVariant(source.getPlatformVariant());
        if (source.getOrchestrator() != null) {
            stackJson.setOrchestrator(conversionService.convert(source.getOrchestrator(), OrchestratorResponse.class));
        }
        stackJson.setCreated(source.getCreated());
        stackJson.setGatewayPort(source.getGatewayPort());
        return stackJson;
    }

    private Set<InstanceGroupJson> convertInstanceGroups(Set<InstanceGroup> instanceGroups) {
        return (Set<InstanceGroupJson>) getConversionService().convert(instanceGroups, TypeDescriptor.forObject(instanceGroups),
                TypeDescriptor.collection(Set.class, TypeDescriptor.valueOf(InstanceGroupJson.class)));
    }

}
