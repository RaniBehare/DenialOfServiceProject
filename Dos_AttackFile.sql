show databases;

create database Attack_Detection;
use Attack_Detection;
create table Attacks(id integer, attack_type integer, attack_date datetime, source_ip varchar(30) );
insert into Attacks values(1,1,"2024-01-01 12:12:00", "192.168.1.100");
insert into Attacks values(2,2,"2024-01-02 13:11:10", "192.168.1.110");
insert into Attacks values(3,3,"2024-02-03 13:12:20", "192.168.1.120");
insert into Attacks values(4,1,"2024-01-04 14:12:00", "192.168.1.130");
insert into Attacks values(5,2,"2024-01-01 15:15:00", "192.168.1.140");
select * from Attacks;

create table Attack_types (id integer, type_name varchar(100), descriptions varchar(100));
insert into Attack_types values (1, "DDoS", "Distributed Denial of Service"),  (2, "SQL Injection", "Structured Query Language Injection"), (3, "Cross-Site Scripting", "XSS");
select * from Attack_types;

create table Sources (id integer, source_ip varchar(50), source_country varchar(50));
insert into Sources values  (1, "192.168.1.100", "USA"), (2, "192.168.1.101", "China"), (3, "192.168.1.102", "Russia"), (4, "192.168.1.103", "India"), (5, "192.168.1.104", "Brazil");
select * from Sources;

create table Detection_rules (id integer, rule_name varchar(100), rule_description varchar(100));
insert into Detection_rules values (1, "Rule 1", "Detect DDoS attacks"), (2, "Rule 2", "Detect SQL Injection"), (3, "Rule 3", "Detect XSS"), (4, "Rule 4", "Detect Brute Force"), (5, "Rule 5", "Detect Phishing");
select * from Detection_rules;

create table Alerts (id integer, attack_id integer, alert_date datetime, alert_level varchar(50));
insert into Alerts values  (1, 1, "2022-01-01 12:00:00", "High"), (2, 2, "2022-01-02 13:00:00", "Medium"),  (3, 3, "2022-01-03 14:00:00", "Low"), (4, 4, "2022-01-04 15:00:00", "High"), (5, 5, "2022-01-05 16:00:00", "Medium");
select * from Alerts;


create database Network_Traffic;
use Network_Traffic;
create table traffic (id integer, overall_timestamp datetime, source_ip varchar(40), destination_ip varchar(50), protocol varchar(50));
insert into traffic values (1, "2022-01-01 12:00:00", "192.168.1.100", "192.168.1.1", "TCP"), (2, "2022-01-02 13:00:00", "192.168.1.101", "192.168.1.2", "UDP"), (3, "2022-01-03 14:00:00", "192.168.1.102", "192.168.1.3", "HTTP"),  (4, "2022-01-04 15:00:00", "192.168.1.103", "192.168.1.4", "FTP"), (5, "2022-01-05 16:00:00", "192.168.1.104", "192.168.1.5", "SSH");
select * from traffic;

create table  protocols (id integer, protocol_name varchar(50), protocol_description varchar(50));
insert into protocols values  (1, "TCP", "Transmission Control Protocol"), (2, "UDP", "User Datagram Protocol"),  (3, "HTTP", "Hypertext Transfer Protocol"), (4, "FTP", "File Transfer Protocol"), (5, "SSH", "Secure Shell");
select * from protocols;

create table ip_addresses (id integer, ip_address varchar(50), ip_type varchar(50));
insert into ip_addresses values  (1, "192.168.1.100", "Public"), (2, "192.168.1.101", "Private"), (3, "192.168.1.102", "Public"), (4, "192.168.1.103", "Private"), (5, "192.168.1.104", "Public");
select * from ip_addresses;

create table network_devices (id integer, device_name varchar(50), device_type varchar(50));
insert into network_devices values (1, "Router", "Cisco"), (2, "Switch", "HP"), (3, "Firewall", "Juniper"), (4, "Server", "Dell"), (5, "Client", "Laptop");
select * from network_devices;

create table  traffic_status (id integer, overall_timestamp datetime, traffic_volume integer);
insert into traffic_status (id, overall_timestamp, traffic_volume) values (1, '2024-09-17 08:30:00', 120), (2, '2024-09-17 09:00:00', 85), (3, '2024-09-17 09:30:00', 50), (4, '2024-09-17 10:00:00', 200), (5, '2024-09-17 10:30:00', 150);
select * from traffic_status;

create database System_Resources;
use System_Resources;
create table resource_usage ( id INTEGER PRIMARY KEY, timestamp DATETIME, cpu_usage DECIMAL(5, 2), memory_usage DECIMAL(7, 2), disk_usage DECIMAL(7, 2));
insert into resource_usage (id, timestamp, cpu_usage, memory_usage, disk_usage) values (1, '2024-09-17 08:30:00', 45.75, 2048.50, 50000.75),(2, '2024-09-17 09:00:00', 60.25, 3072.00, 50500.00),(3, '2024-09-17 09:30:00', 55.50, 4096.75, 51025.25),(4, '2024-09-17 10:00:00', 70.10, 5120.25, 52000.00),(5, '2024-09-17 10:30:00', 65.35, 6144.00, 53075.50);
select * from resource_usage;

create table resources (id INTEGER, resource_name VARCHAR(100) NOT NULL, resource_description varchar(50));
insert into resources (id, resource_name, resource_description) values (1, 'CPU', 'Central Processing Unit responsible for executing instructions.'),
(2, 'Memory', 'RAM used for temporary data storage and processing.'),
(3, 'Disk', 'Storage device used for saving and retrieving data.'),
(4, 'Network Interface', 'Handles network communication and data transfer.'),
(5, 'GPU', 'Graphics Processing Unit for handling rendering and computations.');
select * from resources;

create table system_stats (id integer, timestamp datetime, system_load decimal(4, 2),   system_uptime integer );
insert into system_stats (id, timestamp, system_load, system_uptime) values
(1, '2024-09-17 08:30:00', 15.75, 120),
(2, '2024-09-17 09:00:00', 20.50, 180),
(3, '2024-09-17 09:30:00', 25.30, 240),
(4, '2024-09-17 10:00:00', 18.65, 300),
(5, '2024-09-17 10:30:00', 22.80, 360);
select * from system_stats;

create table process_list (id integer, process_name varchar(100) NOT NULL, process_pid integer NOT NULL,process_cpu_usage decimal(5, 2) );
insert into process_list (id, process_name, process_pid, process_cpu_usage) values
(1, 'chrome.exe', 1234, 12.45),
(2, 'python.exe', 5678, 8.30),
(3, 'java.exe', 9101, 15.20),
(4, 'explorer.exe', 1121, 5.75),
(5, 'notepad.exe', 3141, 1.50);
select * from process_list;

create table user_sessions (id integer, user_id integer, session_start datetime,session_end datetime);
insert into user_sessions (id, user_id, session_start, session_end) values
(1, 101, '2024-09-17 08:30:00', '2024-09-17 09:00:00'),
(2, 102, '2024-09-17 09:15:00', '2024-09-17 10:00:00'),
(3, 103, '2024-09-17 10:05:00', NULL),  
(4, 104, '2024-09-17 11:00:00', '2024-09-17 11:45:00'),
(5, 105, '2024-09-17 12:00:00', '2024-09-17 12:30:00');
select * from user_sessions;


create database Incident_Response;
use Incident_Response;
create table incident_types ( id int primary key, type_name varchar(100) not null, type_description varchar(200));
insert into incident_types (id, type_name, type_description) values
(1, 'Network Outage', 'Disruptions in network connectivity, affecting internal or external networks.'),
(2, 'Security Breach', 'Unauthorized access or data breach compromising system security.'),
(3, 'Hardware Failure', 'Malfunction of physical hardware components such as servers or storage devices.'),
(4, 'Software Bug', 'Software errors causing system instability or incorrect behavior.'),
(5, 'Power Failure', 'Loss of power affecting system operations.');
select * from incident_types;

create table incidents ( id int primary key auto_increment, incident_date datetime NOT NULL, incident_type int NOT NULL, incident_description varchar(100), foreign key (incident_type) references incident_types(id));
insert into incidents (incident_date, incident_type, incident_description) values
('2024-09-15 14:30:00', 1, 'Network outage affecting the main office. Unable to access the internal network.'),
('2024-09-16 09:45:00', 2, 'Detected unauthorized access to the customer database. Investigating potential data breach.'),
('2024-09-17 08:20:00', 3, 'Server hardware failure in the data center. Initiating replacement procedures.'),
('2024-09-18 11:00:00', 4, 'Software bug causing intermittent crashes of the CRM system.'),
('2024-09-19 13:15:00', 5, 'Power failure in the building. Backup generators activated.');
select * from incidents;


create table response_plans ( id int primary key AUTO_INCREMENT,plan_name varchar(255) NOT NULL,plan_description varchar(200));
insert into response_plans (plan_name, plan_description) values
('Network Outage Response Plan', 'A step-by-step guide to restore network connectivity including escalation procedures and communication plans.'),
('Security Breach Response Plan', 'Procedures for identifying, containing, and mitigating security breaches, including coordination with cybersecurity experts.'),
('Hardware Failure Response Plan', 'Instructions for diagnosing hardware issues, replacing faulty components, and restoring system operations.'),
('Software Bug Response Plan', 'Guidelines for identifying, reporting, and resolving software bugs with minimal disruption to services.'),
('Power Failure Response Plan', 'Plan outlining actions to take in case of a power outage, including the use of backup power sources.');
select * from response_plans;

create table response_teams (id int primary key auto_increment,team_name varchar(255) NOT NULL,team_lead varchar(255) NOT NULL);
insert into response_teams (team_name, team_lead) values
('network support team', 'alice smith'),
('cybersecurity response team', 'john doe'),
('hardware maintenance team', 'maria garcia'),
('software development team', 'james johnson'),
('power management team', 'emma davis');
select * from response_teams;

create table incident_reports (id int primary key auto_increment,incident_id int not null, report_date datetime not null,report_description text,foreign key (incident_id) references incidents(id));
insert into incident_reports (incident_id, report_date, report_description) values
(1, '2024-09-15 16:00:00', 'Initial investigation completed for network outage. Issue identified with the main router.'),
(2, '2024-09-16 10:30:00', 'Security breach contained. Unauthorized access point disabled.'),
(3, '2024-09-17 09:00:00', 'Hardware failure isolated to server 03. Replacement part ordered.'),
(4, '2024-09-18 12:30:00', 'Software bug fix implemented. Monitoring system stability.'),
(5, '2024-09-19 14:00:00', 'Power failure response successful. Systems running on backup generators.');
select * from incident_reports;

create database Security_Information;
use Security_Information;

create table vulnerabilities (id int primary key auto_increment, vuln_name varchar(255) not null,vuln_description text,vuln_severity varchar(50) not null);
insert into vulnerabilities (vuln_name, vuln_description, vuln_severity) values
('SQL Injection', 'An attacker can execute arbitrary SQL code on a database, potentially accessing or modifying data.', 'High'),
('Cross-Site Scripting (XSS)', 'Allows attackers to inject malicious scripts into web pages viewed by other users.', 'Medium'),
('Buffer Overflow', 'Occurs when a program writes data beyond the bounds of pre-allocated fixed-size buffers, potentially causing crashes or arbitrary code execution.', 'Critical'),
('Denial of Service (DoS)', 'An attack aimed at making a machine or network resource unavailable to its intended users by overwhelming it with requests.', 'Low'),
('Privilege Escalation', 'An attacker gains elevated access to resources that are normally protected from an application or user.', 'High');
select * from vulnerabilities;

create table patches (id int primary key auto_increment, patch_name varchar(255) not null,patch_description text,patch_release_date datetime not null);
insert into patches (patch_name, patch_description, patch_release_date) values
('Patch 1.0.1', 'Fixes a critical security vulnerability in the authentication module.', '2024-08-01 10:00:00'),
('Patch 1.0.2', 'Addresses multiple bugs and improves system stability.', '2024-08-15 14:30:00'),
('Patch 1.0.3', 'Enhances encryption protocols to strengthen data security.', '2024-09-01 09:45:00'),
('Patch 1.0.4', 'Introduces performance improvements and resolves minor UI issues.', '2024-09-10 11:20:00'),
('Patch 1.0.5', 'Provides compatibility with the latest operating system update.', '2024-09-20 16:00:00');
select * from patches;

create table security_advisories (id int primary key auto_increment,advisory_name varchar(255) not null,advisory_description text);
insert into security_advisories (advisory_name, advisory_description) values
('Advisory 2024-001', 'Warning about a critical vulnerability in the latest version of the web server software. Immediate patching is recommended.'),
('Advisory 2024-002', 'New phishing campaign targeting corporate email accounts. Users are advised to be cautious of suspicious emails.'),
('Advisory 2024-003', 'Security notice regarding potential zero-day exploits in outdated operating systems. Update to the latest version is advised.'),
('Advisory 2024-004', 'Advisory on recent malware outbreaks affecting file storage systems. Implementing enhanced monitoring is recommended.'),
('Advisory 2024-005', 'Alert about a data breach affecting multiple organizations using a popular content management system. Prompt review of system logs is recommended.');
select * from security_advisories;

create table threat_intelligence (id int primary key auto_increment, threat_name varchar(255) not null,threat_description text,threat_level varchar(50) not null );
insert into threat_intelligence (threat_name, threat_description, threat_level) values
('Advanced Persistent Threat (APT)', 'A prolonged and targeted cyberattack in which an intruder gains access to a network and remains undetected for an extended period.', 'Critical'),
('Ransomware', 'Malware that encrypts the victim\'s files, with the attacker demanding a ransom for the decryption key.', 'High'),
('Phishing', 'A technique used by attackers to trick individuals into providing sensitive information by pretending to be a trustworthy entity.', 'Medium'),
('Distributed Denial of Service (DDoS)', 'An attack that attempts to make an online service unavailable by overwhelming it with a large amount of traffic.', 'High'),
('Zero-Day Exploit', 'A cyberattack that occurs on the same day a weakness is discovered in software, before a fix is available.', 'Critical');
select * from threat_intelligence;

create table Security_Information.security_incidents (id int primary key auto_increment,incident_id int not null,security_incident_date datetime not null,foreign key (incident_id) references Incident_Response.incidents(id));
insert into Security_Information.security_incidents (incident_id, security_incident_date) values
(1, '2024-09-15 15:00:00'),  
(2, '2024-09-16 11:00:00'),  
(3, '2024-09-17 10:30:00');
select * from security_incidents;

-- queries for attack types table
use Attack_Detection;
select * from attack_types;
select * from attack_types where type_name = 'ddos';
select * from attack_types where descriptions like '%flooding%';

-- queries for source table
select * from sources;
select * from sources where source_ip = '192.168.1.100';
select * from sources where source_country = 'usa';

-- queries for detection rules table
select * from detection_rules;
select * from detection_rules where rule_name = 'rule 1';
select * from detection_rules where rule_description like '%ddos%';

-- queries for alerts table
select * from alerts;
select * from alerts where alert_level = 'High';
select * from alerts where alert_date between '2022-01-01' and '2022-01-31';

