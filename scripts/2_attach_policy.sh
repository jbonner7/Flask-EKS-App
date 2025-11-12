#!/bin/bash
# ----------------------------------------------------------------
# SCRIPT 2: Attach ECR Read Policy to Worker Node Role 
# ----------------------------------------------------------------

NODE_ROLE_NAME=""                                                                                            

aws iam attach-role-policy \
	--role-name $NODE_ROLE_NAME     
	--policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly