package com.sequenceiq.cloudbreak.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.sequenceiq.cloudbreak.api.endpoint.EventEndpoint;
import com.sequenceiq.cloudbreak.domain.CbUser;
import com.sequenceiq.cloudbreak.facade.CloudbreakEventsFacade;
import com.sequenceiq.cloudbreak.logger.MDCBuilder;
import com.sequenceiq.cloudbreak.api.model.CloudbreakEventsJson;

@Component
public class CloudbreakEventController implements EventEndpoint {

    @Autowired
    private CloudbreakEventsFacade cloudbreakEventsFacade;

    @Autowired
    private AuthenticatedUserService authenticatedUserService;

    @Override
    public List<CloudbreakEventsJson> get(Long since) {
        CbUser user = authenticatedUserService.getCbUser();
        MDCBuilder.buildUserMdcContext(user);
        List<CloudbreakEventsJson> cloudbreakEvents = cloudbreakEventsFacade.retrieveEvents(user.getUserId(), since);
        return cloudbreakEvents;
    }
}
