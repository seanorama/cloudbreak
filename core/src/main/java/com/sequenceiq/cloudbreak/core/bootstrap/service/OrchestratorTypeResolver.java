package com.sequenceiq.cloudbreak.core.bootstrap.service;

import java.util.Map;

import javax.annotation.Resource;

import com.sequenceiq.cloudbreak.orchestrator.host.HostOrchestrator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.sequenceiq.cloudbreak.core.CloudbreakException;
import com.sequenceiq.cloudbreak.orchestrator.container.ContainerOrchestrator;

@Component
public class OrchestratorTypeResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(OrchestratorTypeResolver.class);

    @Resource
    private Map<String, HostOrchestrator> hostOrchestrators;

    @Resource
    private Map<String, ContainerOrchestrator> containerOrchestrators;

    public OrchestratorType resolveType(String name) throws CloudbreakException {
        if (hostOrchestrators.keySet().contains(name)) {
            return OrchestratorType.HOST;
        } else if (containerOrchestrators.keySet().contains(name)) {
            return OrchestratorType.CONTAINER;
        } else {
            LOGGER.error("Orchestrator not found: {}", name);
            throw new CloudbreakException("Orchestrator not found: " + name);
        }
    }


}
