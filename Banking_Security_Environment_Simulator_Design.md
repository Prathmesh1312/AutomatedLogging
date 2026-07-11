# Banking Security Environment Simulator (BSES)

## Overview

The **Banking Security Environment Simulator (BSES)** is a standalone
microservice that continuously simulates a realistic banking ecosystem
and generates high-quality security logs for downstream security
platforms.

Its purpose is **not** to detect threats, but to **produce realistic
operational and security telemetry** that can be consumed by:

-   SIEM Platform
-   Threat Intelligence Engine
-   Machine Learning Anomaly Detection
-   SOC Dashboard
-   Incident Response Engine

------------------------------------------------------------------------

# Objectives

-   Simulate an enterprise-scale bank.
-   Generate correlated (not random) security events.
-   Produce continuous live log streams.
-   Simulate both normal and malicious behavior.
-   Maintain persistent state for users, devices, and infrastructure.
-   Support configurable attack scenarios.
-   Provide ground-truth labels for evaluating detection accuracy.

------------------------------------------------------------------------

# High-Level Architecture

``` text
                    Scenario Engine
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
 User Simulator     Employee Simulator   Device Simulator
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                    Event Generator
                           │
          ┌────────────────┼─────────────────┐
          │                │                 │
 Authentication     Transaction      Infrastructure
      Logs             Logs               Logs
          │                │                 │
          └────────────────┼─────────────────┘
                           │
                  Threat Injection Engine
                           │
                    Log Streaming API
                           │
                Kafka / WebSocket / REST
                           │
                  Downstream SIEM Platform
```

------------------------------------------------------------------------

# Core Components

## 1. Bank World Model

Create a persistent virtual bank consisting of:

-   Branches
-   Customers
-   Employees
-   ATMs
-   APIs
-   Servers
-   Databases
-   Firewalls
-   Network Devices

Example:

``` text
20 Branches
500 Employees
100,000 Customers
400 ATMs
20 APIs
50 Servers
10 Databases
```

------------------------------------------------------------------------

## 2. Customer Simulator

Each customer has a persistent profile.

Example:

``` json
{
  "customerId":"C10231",
  "preferredDevice":"Android",
  "usualLoginTime":"19:00-22:00",
  "averageTransaction":2500,
  "riskLevel":"LOW"
}
```

Typical actions:

-   Login
-   Check Balance
-   View Statement
-   UPI Payment
-   Bank Transfer
-   Logout

------------------------------------------------------------------------

## 3. Employee Simulator

Each employee has:

-   Role
-   Department
-   Privileges
-   Working Hours
-   Assigned Branch
-   Allowed Systems

Example:

``` json
{
  "employeeId":"EMP211",
  "role":"Loan Officer",
  "department":"Loans"
}
```

------------------------------------------------------------------------

## 4. Device Simulator

Simulate:

-   Android
-   iPhone
-   Chrome
-   Safari
-   ATM Terminal
-   POS Machine
-   Branch Workstation

Each device stores:

-   Device ID
-   OS
-   Browser
-   Fingerprint
-   MAC Address
-   Geo-location

------------------------------------------------------------------------

## 5. Branch Simulator

Each branch contains:

-   Employees
-   ATMs
-   Local Network
-   VPN Gateway
-   Firewall
-   Database Replica

------------------------------------------------------------------------

# Event Generator

Continuously creates realistic workflows.

Customer:

``` text
Login
↓
Balance Check
↓
Transfer
↓
Logout
```

Employee:

``` text
Login
↓
Approve Loan
↓
Update Customer
↓
Logout
```

ATM:

``` text
Insert Card
↓
PIN Verification
↓
Withdraw Cash
↓
Receipt
```

------------------------------------------------------------------------

# Log Categories

## Authentication Logs

``` json
{
  "event":"LOGIN_SUCCESS",
  "user":"alice",
  "ip":"49.x.x.x",
  "device":"Android",
  "mfa":true
}
```

## Transaction Logs

``` json
{
  "event":"TRANSFER",
  "amount":2500,
  "currency":"INR"
}
```

## API Logs

``` json
{
  "endpoint":"/api/v1/transfer",
  "status":200
}
```

## Database Logs

``` json
{
  "query":"SELECT",
  "table":"Accounts"
}
```

## Firewall Logs

``` json
{
  "action":"BLOCK",
  "port":22
}
```

## Endpoint Logs

``` json
{
  "process":"powershell.exe"
}
```

------------------------------------------------------------------------

# Scenario Engine

Creates realistic daily activity.

### Morning

-   Employee logins
-   Salary credits
-   ATM withdrawals

### Afternoon

-   Loan approvals
-   Customer transfers
-   API traffic

### Evening

-   Mobile banking
-   Shopping
-   UPI payments

### Night

-   Backups
-   Batch jobs
-   Fraud attempts

### Weekend

-   High ATM activity
-   Lower employee activity

------------------------------------------------------------------------

# Threat Injection Engine

Injects realistic attacks.

## Brute Force

``` text
15 Failed Logins
↓
Successful Login
```

## Impossible Travel

``` text
Mumbai
↓
5 Minutes
↓
London
```

## Insider Threat

``` text
Employee Login
↓
Customer Database
↓
Export CSV
↓
Delete Logs
```

## SQL Injection

``` text
/api/login
↓
' OR 1=1
```

## Malware

``` text
powershell.exe
↓
Encoded Command
↓
C2 Connection
```

## Data Exfiltration

``` text
Export Database
↓
ZIP
↓
Cloud Upload
```

## Ransomware

``` text
Encrypt Files
↓
Delete Shadow Copies
```

------------------------------------------------------------------------

# LLM Behavior Engine

The LLM acts as a stateful simulator rather than a random generator.

Example prompt:

> You are simulating a banking customer. Maintain consistent behavior
> based on previous actions. Generate realistic SIEM events in JSON
> only. Occasionally participate in attack scenarios when instructed.

This enables coherent event sequences.

------------------------------------------------------------------------

# Time Engine

Behavior changes based on:

-   Hour of day
-   Day of week
-   Month end
-   Salary day
-   Holidays

------------------------------------------------------------------------

# Risk Labels

Each event may include:

``` json
{
  "attack": true,
  "risk": "HIGH",
  "groundTruth": "Brute Force"
}
```

Useful for evaluating detection performance.

------------------------------------------------------------------------

# Output Interfaces

-   WebSocket
-   REST API
-   Kafka
-   JSONL Export
-   CSV Export
-   MongoDB
-   Elasticsearch

------------------------------------------------------------------------

# Configuration

Configurable parameters:

-   Customers
-   Employees
-   Branches
-   ATMs
-   Events per second
-   Attack frequency
-   Attack types
-   Geographic distribution
-   Simulation speed

------------------------------------------------------------------------

# Future Enhancements

-   Digital twin of multiple banks
-   Fraud ring simulation
-   Adaptive attacker personas
-   Generative customer behavior
-   Seasonal transaction patterns
-   Multi-region infrastructure
-   Cloud service logs
-   Active Directory simulation
-   Email gateway simulation
-   DNS and proxy logs

------------------------------------------------------------------------

# Deliverables

This service continuously produces:

-   Authentication logs
-   Transaction logs
-   ATM logs
-   API logs
-   Database logs
-   Firewall logs
-   Endpoint logs
-   Threat scenarios
-   Ground-truth attack labels
-   Real-time event streams

These outputs become the input for the SIEM, threat intelligence,
anomaly detection, and SOC dashboard.
