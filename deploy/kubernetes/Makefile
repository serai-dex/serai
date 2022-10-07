SHELL := /bin/bash

check-helm:
	@helm version || $(MAKE) install-helm

check-kubectl:
	@kubectl version || $(MAKE) install-kubectl

install-helm:
	@curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
	@chmod 700 get_helm.sh
	@./get_helm.sh
	@rm get_helm.sh

install-kubectl:
	@curl -LO 'https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl'
	@sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
	@rm kubectl

deploy-base:
	@docker compose -f ../docker-compose.yml --profile base build --quiet
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-base charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-base,nameOverride=serai-base,image.envVariables[1].value=base,configMapFile=%

deploy-bitcoin:
	@docker compose -f ../docker-compose.yml --profile bitcoin build --quiet
	@(cat ../coins/bitcoin/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install bitcoin-daemon charts/bitcoin/ --values \
	charts/bitcoin/values.yaml --set configMapFile=%
	
deploy-ethereum:
	@docker compose -f ../docker-compose.yml --profile ethereum build --quiet
	@(cat ../coins/ethereum/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install ethereum-daemon charts/ethereum/ --values \
	charts/ethereum/values.yaml --set configMapFile=%
	
deploy-monero:
	@docker compose -f ../docker-compose.yml --profile monero build --quiet
	@(cat ../coins/monero/scripts/entry-dev.sh | base64 -w 0 -) | xargs -I \
	% helm upgrade --install monero-daemon charts/monero/ --values \
	charts/monero/values.yaml --set configMapFile=%

deploy-cluster-sm:
	@docker compose -f ../docker-compose.yml --profile cluster-sm build --quiet
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-alice charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-alice,nameOverride=serai-alice,image.envVariables[1].value=\
	Alice,image.envVariables[2].value="'1'",configMapFile=%
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-charlie charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-charlie,nameOverride=serai-charlie,image.envVariables[1].value=\
	Charlie,configMapFile=%
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-bob charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-bob,nameOverride=serai-bob,image.envVariables[1].value=Bob,configMapFile=%

deploy-cluster-lg: deploy-cluster-sm
	@docker compose -f ../docker-compose.yml --profile cluster-lg build --quiet
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-dave charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-dave,nameOverride=serai-dave,image.envVariables[1].value=\
	Dave,configMapFile=%
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-eve charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-eve,nameOverride=serai-eve,image.envVariables[1].value=Eve,configMapFile=%
	@(cat ../serai/scripts/entry-dev.sh | base64 -w 0 -) | xargs \
	-I % helm upgrade --install serai-ferdie charts/serai/ --values \
	charts/serai/values.yaml --set image.envVariablesfullnameOverride=\
	serai-ferdie,nameOverride=serai-ferdie,image.envVariables[1].value=Ferdie,configMapFile=%
	
deploy-coins: deploy-bitcoin deploy-ethereum deploy-monero

deploy-cluster-coins-sm: deploy-cluster-sm deploy-coins
	
deploy-cluster-coins-lg: deploy-cluster-lg deploy-coins
	
deploy-all: deploy-cluster-coins-lg

delete-base:
	@helm delete serai-base

delete-bitcoin:
	@helm delete bitcoin-daemon
	
delete-ethereum:
	@helm delete ethereum-daemon
	
delete-monero:
	@helm delete monero-daemon

delete-cluster-lg: delete-cluster-sm
	@helm delete serai-dave
	@helm delete serai-eve
	@helm delete serai-ferdie
	
delete-cluster-sm:
	@helm delete serai-alice
	@helm delete serai-charlie
	@helm delete serai-bob 

delete-coins: delete-bitcoin delete-ethereum delete-monero

delete-cluster-coins-sm: delete-cluster-sm delete-coins
	
delete-cluster-coins-lg: delete-cluster-lg delete-coins
	
delete-all: delete-cluster-coins-lg

check-dependencies: check-helm check-kubectl
