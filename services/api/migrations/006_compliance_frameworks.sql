-- Migration 006: Additional compliance frameworks (ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA)
-- Run after 005_compliance.sql

BEGIN;

-- ISO 27001:2022 controls
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('iso27001', 'A.5.1', 'Organizational Controls', 'Policies for information security', 'Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to, and acknowledged by relevant personnel.'),
  ('iso27001', 'A.5.2', 'Organizational Controls', 'Information security roles and responsibilities', 'Information security roles and responsibilities shall be defined and allocated according to the organizational needs.'),
  ('iso27001', 'A.5.10', 'Organizational Controls', 'Acceptable use of information and other associated assets', 'Rules for the acceptable use and procedures for handling information and other associated assets shall be identified, documented and implemented.'),
  ('iso27001', 'A.5.15', 'Organizational Controls', 'Access control', 'Rules to control physical and logical access to information and other associated assets shall be established and implemented.'),
  ('iso27001', 'A.5.16', 'Organizational Controls', 'Identity management', 'The full life cycle of identities shall be managed.'),
  ('iso27001', 'A.5.17', 'Organizational Controls', 'Authentication information', 'Allocation and management of authentication information shall be controlled by a management process.'),
  ('iso27001', 'A.5.18', 'Organizational Controls', 'Access rights', 'Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed.'),
  ('iso27001', 'A.5.26', 'Organizational Controls', 'Response to information security incidents', 'Information security incidents shall be responded to in accordance with the documented procedures.'),
  ('iso27001', 'A.5.28', 'Organizational Controls', 'Collection of evidence', 'The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence.'),
  ('iso27001', 'A.6.2', 'People Controls', 'Terms and conditions of employment', 'Employment contractual agreements shall state the personnel''s and the organization''s responsibilities for information security.'),
  ('iso27001', 'A.6.8', 'People Controls', 'Information security event reporting', 'Personnel shall be provided with a mechanism to report information security events through appropriate channels in a timely manner.'),
  ('iso27001', 'A.7.1', 'Physical Controls', 'Physical security perimeters', 'Security perimeters shall be defined and used to protect areas that contain information and other associated assets.'),
  ('iso27001', 'A.8.2', 'Technological Controls', 'Privileged access rights', 'The allocation and use of privileged access rights shall be restricted and managed.'),
  ('iso27001', 'A.8.5', 'Technological Controls', 'Secure authentication', 'Secure authentication technologies and procedures shall be implemented based on information access restrictions.'),
  ('iso27001', 'A.8.6', 'Technological Controls', 'Capacity management', 'The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.'),
  ('iso27001', 'A.8.7', 'Technological Controls', 'Protection against malware', 'Protection against malware shall be implemented and supported by appropriate user awareness.'),
  ('iso27001', 'A.8.15', 'Technological Controls', 'Logging', 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.'),
  ('iso27001', 'A.8.16', 'Technological Controls', 'Monitoring activities', 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.'),
  ('iso27001', 'A.8.25', 'Technological Controls', 'Secure development life cycle', 'Rules for the secure development of software and systems shall be established and applied.')
ON CONFLICT (framework, control_id) DO NOTHING;

-- NIST CSF 2.0 controls
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('nist_csf', 'GV.OC-01', 'Govern - Organizational Context', 'Mission and stakeholder expectations', 'The organizational mission is understood and informs cybersecurity risk management.'),
  ('nist_csf', 'GV.RM-01', 'Govern - Risk Management Strategy', 'Risk management objectives', 'Risk management objectives are established and agreed to by organizational stakeholders.'),
  ('nist_csf', 'GV.PO-01', 'Govern - Policy', 'Cybersecurity policy', 'Policy for managing cybersecurity risks is established based on organizational context.'),
  ('nist_csf', 'ID.AM-01', 'Identify - Asset Management', 'Inventories of hardware assets', 'Inventories of hardware managed by the organization are maintained.'),
  ('nist_csf', 'ID.AM-02', 'Identify - Asset Management', 'Inventories of software assets', 'Inventories of software, services, and systems managed by the organization are maintained.'),
  ('nist_csf', 'ID.RA-01', 'Identify - Risk Assessment', 'Vulnerabilities are identified', 'Vulnerabilities in assets are identified, validated, and recorded.'),
  ('nist_csf', 'PR.AA-01', 'Protect - Identity Management', 'Identities and credentials are managed', 'Identities and credentials for authorized users, services, and hardware are managed.'),
  ('nist_csf', 'PR.AA-03', 'Protect - Identity Management', 'Users and devices are authenticated', 'Users, services, and hardware are authenticated.'),
  ('nist_csf', 'PR.AA-05', 'Protect - Identity Management', 'Access permissions are managed', 'Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.'),
  ('nist_csf', 'PR.DS-01', 'Protect - Data Security', 'Data-at-rest is protected', 'The confidentiality, integrity, and availability of data-at-rest are protected.'),
  ('nist_csf', 'PR.DS-02', 'Protect - Data Security', 'Data-in-transit is protected', 'The confidentiality, integrity, and availability of data-in-transit are protected.'),
  ('nist_csf', 'PR.PS-04', 'Protect - Platform Security', 'Log records are generated', 'Log records are generated and made available for continuous monitoring.'),
  ('nist_csf', 'DE.CM-01', 'Detect - Continuous Monitoring', 'Networks are monitored', 'Networks and network services are monitored to find potentially adverse events.'),
  ('nist_csf', 'DE.CM-03', 'Detect - Continuous Monitoring', 'Personnel activity is monitored', 'Personnel activity and technology usage are monitored to find potentially adverse events.'),
  ('nist_csf', 'DE.AE-02', 'Detect - Adverse Event Analysis', 'Potentially adverse events are analyzed', 'Potentially adverse events are analyzed to better characterize them.'),
  ('nist_csf', 'DE.AE-06', 'Detect - Adverse Event Analysis', 'Information is made available to authorized staff', 'Information on adverse events is provided to authorized staff and tools.'),
  ('nist_csf', 'RS.MA-01', 'Respond - Incident Management', 'Incidents are declared', 'The characteristics of an incident are assessed to inform categorization and prioritization.'),
  ('nist_csf', 'RS.AN-03', 'Respond - Incident Analysis', 'Analysis is performed to establish what has occurred', 'Analysis is performed to establish what has occurred and the root cause of the incident.'),
  ('nist_csf', 'RS.CO-02', 'Respond - Incident Response Reporting', 'Incidents are reported to stakeholders', 'Internal and external stakeholders are notified of incidents.'),
  ('nist_csf', 'RC.RP-01', 'Recover - Incident Recovery Plan', 'Recovery plan is executed', 'The recovery portion of the incident response plan is executed once initiated from the incident response process.')
ON CONFLICT (framework, control_id) DO NOTHING;

-- PCI DSS v4.0 controls
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('pci_dss', '1.1', 'Network Security Controls', 'Processes and mechanisms for network security controls are defined and understood', 'All security policies and operational procedures that are identified in Requirement 1 are documented.'),
  ('pci_dss', '1.2', 'Network Security Controls', 'Network access controls are configured and maintained', 'Network access controls are implemented to control access to systems in the cardholder data environment.'),
  ('pci_dss', '2.1', 'Secure Configurations', 'System components are protected from known vulnerabilities', 'Security features and system configurations are set up to prevent unauthorized access.'),
  ('pci_dss', '3.1', 'Cardholder Data Protection', 'Processes for protecting stored account data are defined and understood', 'All security policies and operational procedures for protecting stored account data are documented.'),
  ('pci_dss', '4.1', 'Strong Cryptography in Transit', 'Strong cryptography is used to safeguard PAN during transmission', 'Strong cryptography is used to safeguard primary account number during transmission over open, public networks.'),
  ('pci_dss', '5.1', 'Malware Protection', 'Processes and mechanisms to protect against malware are defined and understood', 'Anti-malware solutions and processes are deployed to protect all system components from malware.'),
  ('pci_dss', '6.1', 'Secure Systems and Software', 'Processes for protecting bespoke/custom software are defined and understood', 'Security vulnerabilities are identified and addressed in software development processes.'),
  ('pci_dss', '7.1', 'Access Control', 'Processes for implementing access controls are defined and documented', 'Access to system components and cardholder data is limited to only those individuals whose job requires such access.'),
  ('pci_dss', '8.1', 'User Identification and Authentication', 'Processes for implementing user identification and authentication are defined and documented', 'User identification and authentication are managed throughout the account lifecycle.'),
  ('pci_dss', '8.2', 'User Identification and Authentication', 'All user IDs and authentication credentials are managed', 'User IDs and authentication credentials for non-consumer users and administrators are strictly managed.'),
  ('pci_dss', '9.1', 'Physical Access Restriction', 'Processes for protecting cardholder data with physical access controls are defined and understood', 'Physical access controls are implemented for all system components in the CDE.'),
  ('pci_dss', '10.1', 'Log and Monitor All Access', 'Processes for logging and monitoring are defined and understood', 'All access to system components and cardholder data is logged and monitored.'),
  ('pci_dss', '10.2', 'Log and Monitor All Access', 'Audit logs are implemented to support the detection of anomalies', 'Audit logs that capture all individual user access to cardholder data are implemented.'),
  ('pci_dss', '10.7', 'Log and Monitor All Access', 'Failures of critical security controls are detected, reported, and responded to', 'Failures of critical security controls are detected, alerted, and addressed promptly.'),
  ('pci_dss', '11.1', 'Testing Security', 'Processes for regular testing of security systems and networks are defined and understood', 'Security of systems and networks is tested regularly.'),
  ('pci_dss', '12.1', 'Organization Information Security Policy', 'A comprehensive information security policy is known and communicated to all personnel', 'A comprehensive information security policy is established, published, maintained, and disseminated.')
ON CONFLICT (framework, control_id) DO NOTHING;

-- HIPAA Security Rule controls
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('hipaa', '164.308(a)(1)', 'Administrative Safeguards', 'Security management process', 'Implement policies and procedures to prevent, detect, contain, and correct security violations.'),
  ('hipaa', '164.308(a)(2)', 'Administrative Safeguards', 'Assigned security responsibility', 'Identify the security official responsible for the development and implementation of security policies.'),
  ('hipaa', '164.308(a)(3)', 'Administrative Safeguards', 'Workforce security', 'Implement policies and procedures to ensure all workforce members have appropriate access to ePHI.'),
  ('hipaa', '164.308(a)(4)', 'Administrative Safeguards', 'Information access management', 'Implement policies and procedures for authorizing access to ePHI.'),
  ('hipaa', '164.308(a)(5)', 'Administrative Safeguards', 'Security awareness and training', 'Implement a security awareness and training program for all members of the workforce.'),
  ('hipaa', '164.308(a)(6)', 'Administrative Safeguards', 'Security incident procedures', 'Implement policies and procedures to address security incidents.'),
  ('hipaa', '164.308(a)(7)', 'Administrative Safeguards', 'Contingency plan', 'Establish policies and procedures for responding to an emergency or other occurrence.'),
  ('hipaa', '164.308(a)(8)', 'Administrative Safeguards', 'Evaluation', 'Perform periodic technical and non-technical evaluation of the security posture.'),
  ('hipaa', '164.310(a)(1)', 'Physical Safeguards', 'Facility access controls', 'Implement policies and procedures to limit physical access to electronic information systems.'),
  ('hipaa', '164.310(b)', 'Physical Safeguards', 'Workstation use', 'Implement policies and procedures specifying proper functions performed on workstations.'),
  ('hipaa', '164.310(d)(1)', 'Physical Safeguards', 'Device and media controls', 'Implement policies and procedures governing the receipt and removal of hardware and electronic media.'),
  ('hipaa', '164.312(a)(1)', 'Technical Safeguards', 'Access control', 'Implement technical policies and procedures for electronic information systems allowing access only to authorized persons.'),
  ('hipaa', '164.312(b)', 'Technical Safeguards', 'Audit controls', 'Implement mechanisms that record and examine activity in information systems containing or using ePHI.'),
  ('hipaa', '164.312(c)(1)', 'Technical Safeguards', 'Integrity', 'Implement policies and procedures to protect ePHI from improper alteration or destruction.'),
  ('hipaa', '164.312(d)', 'Technical Safeguards', 'Person or entity authentication', 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.'),
  ('hipaa', '164.312(e)(1)', 'Technical Safeguards', 'Transmission security', 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted.')
ON CONFLICT (framework, control_id) DO NOTHING;

-- DORA controls
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('dora', 'Art.5', 'ICT Risk Management', 'ICT risk management framework', 'Financial entities shall have in place a sound, comprehensive and well-documented ICT risk management framework.'),
  ('dora', 'Art.6', 'ICT Risk Management', 'ICT risk management systems, protocols and tools', 'Financial entities shall use and maintain updated ICT systems, protocols and tools that are appropriate, reliable, and have sufficient capacity.'),
  ('dora', 'Art.7', 'ICT Risk Management', 'ICT systems, protocols and tools', 'Financial entities shall use ICT systems, protocols and tools that are adequate and proportionate to the size of their operations.'),
  ('dora', 'Art.8', 'ICT Risk Management', 'Identification of ICT risks', 'Financial entities shall identify, classify and adequately document all ICT supported business functions.'),
  ('dora', 'Art.9', 'ICT Risk Management', 'Protection and prevention of ICT risks', 'Financial entities shall continuously monitor and control ICT security and functioning of ICT systems and tools.'),
  ('dora', 'Art.10', 'ICT Risk Management', 'Detection of anomalous activities', 'Financial entities shall have mechanisms to promptly detect anomalous activities.'),
  ('dora', 'Art.11', 'ICT Risk Management', 'Response and recovery', 'Financial entities shall put in place a comprehensive ICT business continuity policy.'),
  ('dora', 'Art.12', 'ICT Risk Management', 'Backup policies and restoration and recovery procedures', 'Financial entities shall develop and document backup policies and procedures for restoration of ICT systems.'),
  ('dora', 'Art.13', 'ICT Risk Management', 'Learning and evolving', 'Financial entities shall have the capability to gather information on vulnerabilities and cyber threats.'),
  ('dora', 'Art.17', 'ICT Incident Management', 'ICT-related incident management process', 'Financial entities shall define, establish and implement an ICT-related incident management process.'),
  ('dora', 'Art.18', 'ICT Incident Management', 'Classification of ICT-related incidents', 'Financial entities shall classify ICT-related incidents and determine their impact.'),
  ('dora', 'Art.19', 'ICT Incident Management', 'Reporting of major ICT-related incidents', 'Financial entities shall report major ICT-related incidents to the relevant competent authority.'),
  ('dora', 'Art.24', 'Digital Operational Resilience Testing', 'General requirements for digital operational resilience testing', 'Financial entities shall establish, maintain and review a digital operational resilience testing programme.'),
  ('dora', 'Art.25', 'Digital Operational Resilience Testing', 'Testing of ICT tools and systems', 'Financial entities shall test ICT tools and systems using threat-led penetration testing.'),
  ('dora', 'Art.28', 'ICT Third-Party Risk Management', 'General principles of ICT third-party risk management', 'Financial entities shall manage ICT third-party risk as an integral component of ICT risk.'),
  ('dora', 'Art.30', 'ICT Third-Party Risk Management', 'Key contractual provisions', 'Rights and obligations of the financial entity and ICT third-party service provider shall be clearly allocated and set out in writing.')
ON CONFLICT (framework, control_id) DO NOTHING;

COMMIT;
