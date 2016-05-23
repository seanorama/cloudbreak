package com.sequenceiq.cloudbreak.core.flow2.stack.provision;

import com.sequenceiq.cloudbreak.core.flow2.FlowState;
import com.sequenceiq.cloudbreak.core.flow2.stack.provision.action.CheckImageAction;

public enum StackCreationState implements FlowState<StackCreationState, StackCreationEvent> {
    INIT_STATE,
    STACK_CREATION_FAILED_STATE,
    SETUP_STATE,
    IMAGESETUP_STATE,
    IMAGE_CHECK_STATE(CheckImageAction.class),
    START_PROVISIONING_STATE,
    PROVISIONING_FINISHED_STATE,
    COLLECTMETADATA_STATE,
    TLS_SETUP_STATE,
    BOOTSTRAP_MACHINES_STATE,
    HOST_METADATA_SETUP,
    FINAL_STATE;

    private Class<?> action;

    StackCreationState() {
    }

    StackCreationState(Class<?> action) {
        this.action = action;
    }

    @Override
    public Class<?> action() {
        return action;
    }
}
