package com.sequenceiq.cloudbreak.core.flow2.stack.upscale;

import com.sequenceiq.cloudbreak.cloud.event.instance.CollectMetadataResult;
import com.sequenceiq.cloudbreak.cloud.event.resource.UpscaleStackResult;
import com.sequenceiq.cloudbreak.core.flow.FlowPhases;
import com.sequenceiq.cloudbreak.core.flow2.FlowEvent;
import com.sequenceiq.cloudbreak.reactor.api.event.EventSelectorUtil;
import com.sequenceiq.cloudbreak.reactor.api.event.resource.BootstrapNewNodesResult;
import com.sequenceiq.cloudbreak.reactor.api.event.resource.ExtendHostMetadataResult;

public enum StackUpscaleEvent implements FlowEvent {
    ADD_INSTANCES_EVENT(FlowPhases.ADD_INSTANCES.name()),
    ADD_INSTANCES_FINISHED_EVENT(UpscaleStackResult.selector(UpscaleStackResult.class)),
    ADD_INSTANCES_FAILURE_EVENT(UpscaleStackResult.failureSelector(UpscaleStackResult.class)),
    ADD_INSTANCES_FINISHED_FAILURE_EVENT("ADD_INSTANCES_FINISHED_FAILURE_EVENT"),
    EXTEND_METADATA_EVENT(FlowPhases.EXTEND_METADATA.name()),
    EXTEND_METADATA_FINISHED_EVENT(CollectMetadataResult.selector(CollectMetadataResult.class)),
    EXTEND_METADATA_FAILURE_EVENT(CollectMetadataResult.failureSelector(CollectMetadataResult.class)),
    EXTEND_METADATA_FINISHED_FAILURE_EVENT("EXTEND_METADATA_FINISHED_FAILURE_EVENT"),
    BOOTSTRAP_NEW_NODES_EVENT(FlowPhases.BOOTSTRAP_NEW_NODES.name()),
    BOOTSTRAP_NEW_NODES_FAILURE_EVENT(EventSelectorUtil.failureSelector(BootstrapNewNodesResult.class)),
    EXTEND_HOST_METADATA_EVENT(EventSelectorUtil.selector(BootstrapNewNodesResult.class)),
    EXTEND_HOST_METADATA_FINISHED_EVENT(EventSelectorUtil.selector(ExtendHostMetadataResult.class)),
    EXTEND_HOST_METADATA_FINISHED_FAILURE_EVENT("EXTEND_CONSUL_METADATA_FINISHED_FAILURE_EVENT"),
    EXTEND_HOST_METADATA_FAILURE_EVENT(EventSelectorUtil.failureSelector(ExtendHostMetadataResult.class)),
    UPSCALE_FINALIZED_EVENT("UPSCALESTACKFINALIZED"),
    UPSCALE_FAIL_HANDLED_EVENT("UPSCALEFAILHANDLED");

    private String stringRepresentation;

    StackUpscaleEvent(String stringRepresentation) {
        this.stringRepresentation = stringRepresentation;
    }

    @Override
    public String stringRepresentation() {
        return stringRepresentation;
    }
}
