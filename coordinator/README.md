# Serai Coordinator

Serai Coordinator is a service that serves as a coordination layer for Serai. It is responsible for coordinating the execution of Serai DEX with the various services that Serai DEX depends on, communicating non-consensus matters with validators through a secure channel, and observation of the Serai blockchain to ensure solvency and integrity.

## Build, Run, Test

TBA

## Requirements

* Observation
  * Send events from serai observations to the appropriate processor.
  * Receive instructions from supported validators to publish to substrate.
* Health
  * Scan Status
  * Processor Heartbeats
  * Logging
  * Backups
* Coordination
  * Establish signature parties.
  * Route messages from coordinated signature parties to relevant processor.

## Dependencies

* Apache Kafka
* protobuf-compiler
* libprotobuf-dev

Rust Crates:

* calloop
* rust-rdkafka
* serde


## General Architecture

Serai Coordinator uses Apache Kafka as a message bus to communicate between the processors and coordinator of the local Serai deployment. Through the use of Kafka topics, the coordinator can route messages to the appropriate processor.

Topics:

* `serai-observation` - Observations from the Serai blockchain.
* `chain-observation` - Observations from chains registered by the Serai Coordinator.
* `chain-health` - Heartbeats from the processors about health and chain health.
* `signing` - Messages from the coordinator to processors for signing procedures.

Within the coordinator we have managers, each manager will be responsible for one or more producers, and may be responsible for one or more consumers, all running on separate threads. If a manager is responsible for a consumer, it likely produces or creates its own data. Through initialization, the manager will create the appropriate Kafka producers and consumers, and then start them on their own threads. The manager will then start a supervisor thread that will monitor the health of the manager, restarting  or gracefully stopping other systems   that may have failed.


## Common Module

### Requirements

* Traits for common functionality.
* Common types for common functionality.
* Configuration loading and management.


### Configurations

Configuration is handled through a configuration file that is loaded on startup. The configuration file is a TOML file that contains the following sections:

* general
  * log_level - The log level to use for coordinator console logging.
  * backup_dir - The directory to store backups in.
  * backup_interval - The interval to backup the coordinator state.
* kafka
  * bootstrap.servers
  * client.id
  * group.id
* observation
  * rpc_endpoint
  * polling_interval
* connection
  * rpc_endpoint
  * polling_interval
  * validators
    * public_key
    * endpoint
* health 


## Observation Module

### Requirements

* Observe blockheight update events on the target blockchain.
* Observe instruction events to addresses of interest on the target blockchain.

### Architecture

The observation module is responsible for observing the target blockchain for events of interest. It is responsible for publishing these events to the appropriate Kafka topic. To do this, we will continuously poll the local RPC endpoint for changes or information of interest. Once the information has been captured from the target blockchain, it will be published to the appropriate Kafka topic.

The module will provide a manager with an initialization method that requires the rpc endpoint at instatiation. Once initialized, the manager will then spawn a thread that will continuously poll the RPC endpoint for information of interest. The manager will also provide a method to stop the polling thread. Within the polling operation there will be a check to determine if our in-memory understanding of the chainstate has changed, for example the blockheight. If the chainstate has changed, the manager will publish an update to the chainstate on the appropriate Kafka topic. In the polling operation there will also be a check to determine if there are any events of interest that have occurred on the target blockchain. If there are events of interest such as "Serai Instructions", the manager will publish the event to the appropriate Kafka topic so that downstream consumers can process. The observation module uses a custom polling consumer model, not a kafka message consumer.

## Crypto Module

### Requirements

* Deterministically form signature parties to sign outgoing transactions.
* 

## Connection Module

### Requirements

* Accept requests from other processes to secure connections with a specific list of addresses.
* Consume inbound messages and publish them securely to the appropriate Kafka topic.

The connection module is responsible for establishing secure connections with a list of validators. It will accept requests to establish connections with a list of validators, and then will attempt to establish secure connections with each validator. Once a secure connection has been established, the connection module will publish a messages provided from the CryptoManager to target validators. The connection module will also consume messages from the appropriate Kafka topic, and then will publish the message to the appropriate validator. 

The connection module will also consume inbound messages from libp2p and then will publish the message to the appropriate Kafka topic. 

## Data Module

### Requirements

* Accept requests to store data into appropriate data stores.
* Encrypt data before storing.
* Recover data from appropriate data stores.


The data module will provide a common interface for database drivers so that the coordinator can persist data and coordinate persistence with producers to consumers in other pieces of infrastructure built to serve data or out-of-consensus information for Serai. This module will also be responsible for coordinating backups and recovery of data from the filesystem or other external data stores.
 
