package com.sequenceiq.cloudbreak.orchestrator.salt.domain;

import org.springframework.http.HttpStatus;

import com.sequenceiq.cloudbreak.orchestrator.exception.CloudbreakOrchestratorFailedException;

public class SaltBootResponse {

    private String status;
    private String address;
    private int statusCode;
    private String version;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public void assertError() throws CloudbreakOrchestratorFailedException {
        if (this.getStatusCode() != HttpStatus.OK.value()) {
            throw new CloudbreakOrchestratorFailedException(this.toString());
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("SaltBootResponse{");
        sb.append("status='").append(status).append('\'');
        sb.append(", address='").append(address).append('\'');
        sb.append(", statusCode=").append(statusCode);
        sb.append(", version='").append(version).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
