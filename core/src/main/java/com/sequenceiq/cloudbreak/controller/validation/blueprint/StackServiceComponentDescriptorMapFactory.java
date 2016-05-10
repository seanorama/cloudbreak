package com.sequenceiq.cloudbreak.controller.validation.blueprint;

import java.util.Map;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.api.client.util.Maps;
import com.sequenceiq.cloudbreak.util.JsonUtil;

@Component
public class StackServiceComponentDescriptorMapFactory implements FactoryBean<StackServiceComponentDescriptors> {
    private String stackServiceComponentsJson;
    private Map<String, Integer> minCardinalityReps;
    private Map<String, Integer> maxCardinalityReps;

    public StackServiceComponentDescriptorMapFactory(String stackServiceComponentsJson, Map<String, Integer> minCardinalityReps,
            Map<String, Integer> maxCardinalityReps) {
        this.stackServiceComponentsJson = stackServiceComponentsJson;
        this.minCardinalityReps = minCardinalityReps;
        this.maxCardinalityReps = maxCardinalityReps;
    }

    @Override
    public StackServiceComponentDescriptors getObject() throws Exception {
        Map<String, StackServiceComponentDescriptor> stackServiceComponentDescriptorMap = Maps.newHashMap();
        JsonNode rootNode = JsonUtil.readTree(stackServiceComponentsJson);
        JsonNode itemsNode = rootNode.get("items");
        for (JsonNode itemNode : itemsNode) {
            JsonNode componentsNode = itemNode.get("components");
            for (JsonNode componentNode : componentsNode) {
                JsonNode stackServiceComponentsNode = componentNode.get("StackServiceComponents");
                StackServiceComponentDescriptor componentDesc = createComponentDesc(stackServiceComponentsNode);
                stackServiceComponentDescriptorMap.put(componentDesc.getName(), componentDesc);
            }
        }
        return new StackServiceComponentDescriptors(stackServiceComponentDescriptorMap);
    }

    @Override
    public Class<?> getObjectType() {
        return Map.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

    private StackServiceComponentDescriptor createComponentDesc(JsonNode stackServiceComponentNode) {
        String componentName = stackServiceComponentNode.get("component_name").asText();
        String componentCategory = stackServiceComponentNode.get("component_category").asText();
        int minCardinality = parseMinCardinality(stackServiceComponentNode.get("cardinality").asText());
        int maxCardinality = parseMaxCardinality(stackServiceComponentNode.get("cardinality").asText());
        return new StackServiceComponentDescriptor(componentName, componentCategory, minCardinality, maxCardinality);
    }

    private int parseMinCardinality(String cardinalityString) {
        Integer minCardinality = minCardinalityReps.get(cardinalityString);
        return minCardinality == null ? 0 : minCardinality;
    }

    private int parseMaxCardinality(String cardinalityString) {
        Integer maxCardinality = maxCardinalityReps.get(cardinalityString);
        return maxCardinality == null ? Integer.MAX_VALUE : maxCardinality;
    }
}
