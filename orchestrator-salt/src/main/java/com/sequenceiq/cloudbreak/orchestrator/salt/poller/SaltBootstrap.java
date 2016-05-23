package com.sequenceiq.cloudbreak.orchestrator.salt.poller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.sequenceiq.cloudbreak.orchestrator.OrchestratorBootstrap;
import com.sequenceiq.cloudbreak.orchestrator.exception.CloudbreakOrchestratorFailedException;
import com.sequenceiq.cloudbreak.orchestrator.model.GatewayConfig;
import com.sequenceiq.cloudbreak.orchestrator.model.GenericResponse;
import com.sequenceiq.cloudbreak.orchestrator.model.GenericResponses;
import com.sequenceiq.cloudbreak.orchestrator.salt.client.SaltActionType;
import com.sequenceiq.cloudbreak.orchestrator.salt.client.SaltConnector;
import com.sequenceiq.cloudbreak.orchestrator.salt.client.target.Glob;
import com.sequenceiq.cloudbreak.orchestrator.salt.domain.Minion;
import com.sequenceiq.cloudbreak.orchestrator.salt.domain.SaltAction;
import com.sequenceiq.cloudbreak.orchestrator.salt.states.SaltStates;

public class SaltBootstrap implements OrchestratorBootstrap {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaltBootstrap.class);

    private final SaltConnector sc;
    private final GatewayConfig gatewayConfig;
    private final Set<String> originalTargets;
    private Set<String> targets;

    public SaltBootstrap(SaltConnector sc, GatewayConfig gatewayConfig, Set<String> targets) {
        this.sc = sc;
        this.gatewayConfig = gatewayConfig;
        this.originalTargets = Collections.unmodifiableSet(targets);
        this.targets = targets;
    }

    @Override
    public Boolean call() throws Exception {
        if (!targets.isEmpty()) {
            LOGGER.info("Missing targets for SaltBootstrap: {}", targets);

            SaltAction saltAction = createBootstrap();
            GenericResponses responses = sc.action(saltAction);

            Set<String> failedTargets = new HashSet<>();

            LOGGER.info("Salt run response: {}", responses);
            for (GenericResponse genericResponse : responses.getResponses()) {
                if (genericResponse.getStatusCode() != HttpStatus.OK.value()) {
                    LOGGER.info("Successfully distributed salt run to: " + genericResponse.getAddress());
                    failedTargets.add(genericResponse.getAddress().split(":")[0]);
                }
            }
            targets = failedTargets;

            if (!targets.isEmpty()) {
                LOGGER.info("Missing nodes to run salt: %s", targets);
                throw new CloudbreakOrchestratorFailedException("There are missing nodes from salt: " + targets);
            }
        }

        Map<String, String> networkResult = SaltStates.networkInterfaceIP(sc, Glob.ALL).getResultGroupByIP();
        originalTargets.forEach(ip -> {
            if (!networkResult.containsKey(ip)) {
                LOGGER.info("Salt-minion is not responding on host: {}, yet", ip);
                targets.add(ip);
            }
        });
        if (!targets.isEmpty()) {
            throw new CloudbreakOrchestratorFailedException("There are missing nodes from salt: " + targets);
        }
        return true;
    }

    private SaltAction createBootstrap() {
        SaltAction saltAction = new SaltAction(SaltActionType.RUN);

        if (targets.contains(getGatewayPrivateIp())) {
            saltAction.setServer(getGatewayPrivateIp());
            List<String> roles = new ArrayList<>();
            saltAction.addMinion(createMinion(getGatewayPrivateIp(), roles));
        }
        for (String minionIp : targets) {
            if (!minionIp.equals(getGatewayPrivateIp())) {
                List<String> roles = new ArrayList<>();
                saltAction.addMinion(createMinion(minionIp, roles));
            }
        }
        return saltAction;
    }

    private Minion createMinion(String address, List<String> roles) {
        Minion minion = new Minion();
        minion.setAddress(address);
        minion.setRoles(roles);
        minion.setServer(getGatewayPrivateIp());
        return minion;
    }

    private String getGatewayPrivateIp() {
        return gatewayConfig.getPrivateAddress();
    }

    @Override
    public String toString() {
        return "SaltBootstrap{"
                + "gatewayConfig=" + gatewayConfig
                + ", originalTargets=" + originalTargets
                + ", targets=" + targets
                + '}';
    }
}
