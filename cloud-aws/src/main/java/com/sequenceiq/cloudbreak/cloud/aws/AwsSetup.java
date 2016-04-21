package com.sequenceiq.cloudbreak.cloud.aws;

import java.net.URLDecoder;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeInternetGatewaysRequest;
import com.amazonaws.services.ec2.model.DescribeInternetGatewaysResult;
import com.amazonaws.services.ec2.model.DescribeSubnetsRequest;
import com.amazonaws.services.ec2.model.DescribeSubnetsResult;
import com.amazonaws.services.ec2.model.DescribeVpcAttributeRequest;
import com.amazonaws.services.ec2.model.InternetGateway;
import com.amazonaws.services.ec2.model.InternetGatewayAttachment;
import com.amazonaws.services.ec2.model.Subnet;
import com.amazonaws.services.ec2.model.VpcAttributeName;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.model.AttachedPolicy;
import com.amazonaws.services.identitymanagement.model.GetPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyResult;
import com.amazonaws.services.identitymanagement.model.GetRoleRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesResult;
import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONObject;
import com.sequenceiq.cloudbreak.cloud.Setup;
import com.sequenceiq.cloudbreak.cloud.aws.view.AwsCredentialView;
import com.sequenceiq.cloudbreak.cloud.aws.view.AwsNetworkView;
import com.sequenceiq.cloudbreak.cloud.context.AuthenticatedContext;
import com.sequenceiq.cloudbreak.cloud.exception.CloudConnectorException;
import com.sequenceiq.cloudbreak.cloud.model.CloudStack;
import com.sequenceiq.cloudbreak.cloud.model.FileSystem;
import com.sequenceiq.cloudbreak.cloud.model.Group;
import com.sequenceiq.cloudbreak.cloud.model.Image;
import com.sequenceiq.cloudbreak.cloud.notification.PersistenceNotifier;
import com.sequenceiq.cloudbreak.common.type.ImageStatus;
import com.sequenceiq.cloudbreak.common.type.ImageStatusResult;

@Component
public class AwsSetup implements Setup {
    private static final Logger LOGGER = LoggerFactory.getLogger(AwsSetup.class);
    private static final String IGW_DOES_NOT_EXIST_MSG = "The given internet gateway '%s' does not exist or belongs to a different region.";
    private static final String SUBNET_DOES_NOT_EXIST_MSG = "The given subnet '%s' does not exist or belongs to a different region.";
    private static final String SUBNETVPC_DOES_NOT_EXIST_MSG = "The given subnet '%s' does not belong to the given VPC '%s'.";
    private static final String IGWVPC_DOES_NOT_EXIST_MSG = "The given internet gateway '%s' does not belong to the given VPC '%s'.";
    private static final int FINISHED_PROGRESS_VALUE = 100;

    @Value("${cb.aws.spotinstances.enabled:}")
    private boolean awsSpotinstanceEnabled;

    @Inject
    private CloudFormationStackUtil cfStackUtil;

    @Inject
    private AwsClient awsClient;

    @Override
    public void prepareImage(AuthenticatedContext authenticatedContext, CloudStack stack, Image image) {
        LOGGER.debug("prepare image has been executed");
    }

    @Override
    public ImageStatusResult checkImageStatus(AuthenticatedContext authenticatedContext, CloudStack stack, Image image) {
        return new ImageStatusResult(ImageStatus.CREATE_FINISHED, FINISHED_PROGRESS_VALUE);
    }

    @Override
    public void prerequisites(AuthenticatedContext ac, CloudStack stack, PersistenceNotifier persistenceNotifier) {
        AwsNetworkView awsNetworkView = new AwsNetworkView(stack.getNetwork());
        if (!awsSpotinstanceEnabled) {
            for (Group group : stack.getGroups()) {
                if (group.getInstances().get(0).getParameter("spotPrice", Double.class) != null) {
                    throw new CloudConnectorException(String.format("Spot instances are not supported on this AMI: %s", stack.getImage()));
                }
            }
        }
        AwsCredentialView awsCredentialView = new AwsCredentialView(ac.getCloudCredential());
        if (isEnableInstanceProfile(stack) && awsClient.roleBasedCredential(awsCredentialView)) {
            validateInstanceProfileCreation(awsCredentialView);
        }
        if (awsNetworkView.isExistingVPC()) {
            try {
                AmazonEC2Client amazonEC2Client = awsClient.createAccess(new AwsCredentialView(ac.getCloudCredential()),
                        ac.getCloudContext().getLocation().getRegion().value());
                validateExistingVpc(awsNetworkView, amazonEC2Client);
                validateExistingIGW(awsNetworkView, amazonEC2Client);
                validateExistingSubnet(awsNetworkView, amazonEC2Client);
            } catch (AmazonServiceException e) {
                throw new CloudConnectorException(e.getErrorMessage());
            } catch (AmazonClientException e) {
                throw new CloudConnectorException(e.getMessage());
            }

        }
        LOGGER.debug("setup has been executed");
    }

    private void validateInstanceProfileCreation(AwsCredentialView awsCredentialView) {
        GetRoleRequest roleRequest = new GetRoleRequest();
        String roleName = awsCredentialView.getRoleArn().split("/")[1];
        roleRequest.withRoleName(roleName);
        AmazonIdentityManagement client = awsClient.createAmazonIdentityManagement(awsCredentialView);
        try {
            ListRolePoliciesRequest listRolePoliciesRequest = new ListRolePoliciesRequest();
            listRolePoliciesRequest.setRoleName(roleName);
            ListRolePoliciesResult listRolePoliciesResult = client.listRolePolicies(listRolePoliciesRequest);
            for (String s : listRolePoliciesResult.getPolicyNames()) {
                GetRolePolicyRequest getRolePolicyRequest = new GetRolePolicyRequest();
                getRolePolicyRequest.setRoleName(roleName);
                getRolePolicyRequest.setPolicyName(s);
                GetRolePolicyResult rolePolicy = client.getRolePolicy(getRolePolicyRequest);
                String decode = URLDecoder.decode(rolePolicy.getPolicyDocument(), "UTF-8");
                JSONObject object = new JSONObject(decode);
                JSONArray statement = object.getJSONArray("Statement");
                for(int i = 0; i < statement.length(); i++) {
                    JSONArray action = statement.getJSONObject(i).getJSONArray("Action");
                    for(int j = 0; j < action.length(); j++) {
                        if (action.get(j).toString().replaceAll(" ","").equals("iam:*")) {
                            return;
                        }
                    }
                }
            }
            ListAttachedRolePoliciesRequest listAttachedRolePoliciesRequest = new ListAttachedRolePoliciesRequest();
            listAttachedRolePoliciesRequest.setRoleName(roleName);
            ListAttachedRolePoliciesResult listAttachedRolePoliciesResult = client.listAttachedRolePolicies(listAttachedRolePoliciesRequest);
            for (AttachedPolicy attachedPolicy : listAttachedRolePoliciesResult.getAttachedPolicies()) {
                GetPolicyRequest getRolePolicyRequest = new GetPolicyRequest();
                getRolePolicyRequest.setPolicyArn(attachedPolicy.getPolicyArn());
                GetPolicyResult policy = client.getPolicy(getRolePolicyRequest);
                if (policy.getPolicy().getArn().contains("IAM")) {
                    return;
                }
            }
        } catch (AmazonServiceException ase) {
            if (ase.getStatusCode() == 403) {
                LOGGER.info("Could not get policies on the role because the arn role do not have enough permission.");
                throw new CloudConnectorException(ase.getErrorMessage());
            } else {
                LOGGER.info(ase.getMessage());
                throw new CloudConnectorException(ase.getErrorMessage());
            }
        }  catch (Exception e) {
            LOGGER.info(e.getMessage());
            throw new CloudConnectorException(e.getMessage());
        }
        LOGGER.info("Could not get policies on the role because the arn role do not have enough permission.");
        throw new CloudConnectorException("Could not get policies on the role because the arn role do not have enough permission.");
    }

    private boolean isEnableInstanceProfile(CloudStack stack) {
        return stack.getParameters().containsKey("enableInstanceProfile")
                && Boolean.valueOf(stack.getParameters().get("enableInstanceProfile"));
    }

    private boolean isInstanceProfileRole(CloudStack stack) {
        return stack.getParameters().containsKey("instanceProfileRole")
                && Boolean.valueOf(stack.getParameters().get("instanceProfileRole"));
    }

    private void validateExistingVpc(AwsNetworkView awsNetworkView, AmazonEC2Client amazonEC2Client) {
        DescribeVpcAttributeRequest describeVpcAttributeRequest = new DescribeVpcAttributeRequest();
        describeVpcAttributeRequest.withVpcId(awsNetworkView.getExistingVPC());
        describeVpcAttributeRequest.withAttribute(VpcAttributeName.EnableDnsSupport);
        amazonEC2Client.describeVpcAttribute(describeVpcAttributeRequest);
    }

    private void validateExistingSubnet(AwsNetworkView awsNetworkView, AmazonEC2Client amazonEC2Client) {
        if (awsNetworkView.isExistingSubnet()) {
            DescribeSubnetsRequest describeSubnetsRequest = new DescribeSubnetsRequest();
            describeSubnetsRequest.withSubnetIds(awsNetworkView.getExistingSubnet());
            DescribeSubnetsResult describeSubnetsResult = amazonEC2Client.describeSubnets(describeSubnetsRequest);
            if (describeSubnetsResult.getSubnets().size() < 1) {
                throw new CloudConnectorException(String.format(SUBNET_DOES_NOT_EXIST_MSG, awsNetworkView.getExistingSubnet()));
            } else {
                Subnet subnet = describeSubnetsResult.getSubnets().get(0);
                String vpcId = subnet.getVpcId();
                if (vpcId != null && !vpcId.equals(awsNetworkView.getExistingVPC())) {
                    throw new CloudConnectorException(String.format(SUBNETVPC_DOES_NOT_EXIST_MSG, awsNetworkView.getExistingSubnet(),
                            awsNetworkView.getExistingVPC()));
                }
            }
        }
    }

    private void validateExistingIGW(AwsNetworkView awsNetworkView, AmazonEC2Client amazonEC2Client) {
        if (awsNetworkView.isExistingIGW()) {
            DescribeInternetGatewaysRequest describeInternetGatewaysRequest = new DescribeInternetGatewaysRequest();
            describeInternetGatewaysRequest.withInternetGatewayIds(awsNetworkView.getExistingIGW());
            DescribeInternetGatewaysResult describeInternetGatewaysResult = amazonEC2Client.describeInternetGateways(describeInternetGatewaysRequest);
            if (describeInternetGatewaysResult.getInternetGateways().size() < 1) {
                throw new CloudConnectorException(String.format(IGW_DOES_NOT_EXIST_MSG, awsNetworkView.getExistingIGW()));
            } else {
                InternetGateway internetGateway = describeInternetGatewaysResult.getInternetGateways().get(0);
                InternetGatewayAttachment attachment = internetGateway.getAttachments().get(0);
                if (attachment != null && !attachment.getVpcId().equals(awsNetworkView.getExistingVPC())) {
                    throw new CloudConnectorException(String.format(IGWVPC_DOES_NOT_EXIST_MSG, awsNetworkView.getExistingIGW(),
                            awsNetworkView.getExistingVPC()));
                }
            }
        }
    }

    @Override
    public void validateFileSystem(FileSystem fileSystem) throws Exception {
    }
}
