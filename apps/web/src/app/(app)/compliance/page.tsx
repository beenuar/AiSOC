import { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Compliance — AiSOC',
};

const FRAMEWORKS = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'Trust Services Criteria for security, availability, and confidentiality.',
    badge: 'Enterprise',
  },
  {
    id: 'iso27001',
    name: 'ISO/IEC 27001:2022',
    description: 'International standard for information security management systems.',
    badge: 'International',
  },
  {
    id: 'nist_csf',
    name: 'NIST CSF 2.0',
    description: 'NIST Cybersecurity Framework covering Govern, Identify, Protect, Detect, Respond, Recover.',
    badge: 'US Government',
  },
  {
    id: 'pci_dss',
    name: 'PCI DSS v4.0',
    description: 'Payment Card Industry Data Security Standard for cardholder data environments.',
    badge: 'Financial',
  },
  {
    id: 'hipaa',
    name: 'HIPAA Security Rule',
    description: 'Administrative, physical, and technical safeguards for protected health information.',
    badge: 'Healthcare',
  },
  {
    id: 'dora',
    name: 'DORA',
    description: 'EU Digital Operational Resilience Act for financial sector ICT risk management.',
    badge: 'EU Regulation',
  },
];

export default function CompliancePage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Compliance Frameworks</h1>
        <p className="text-gray-400 text-sm mt-1">
          Select a framework to view controls, collect evidence, and export reports.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FRAMEWORKS.map((fw) => (
          <Link
            key={fw.id}
            href={`/compliance/${fw.id}`}
            className="block bg-gray-800 border border-gray-700 rounded-lg p-5 hover:border-blue-500 hover:bg-gray-750 transition-all group"
          >
            <div className="flex items-start justify-between mb-3">
              <h2 className="text-white font-semibold text-base group-hover:text-blue-400 transition-colors">
                {fw.name}
              </h2>
              <span className="ml-2 flex-shrink-0 text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">
                {fw.badge}
              </span>
            </div>
            <p className="text-gray-400 text-sm leading-relaxed">{fw.description}</p>
            <div className="mt-4 text-blue-400 text-xs font-medium group-hover:text-blue-300">
              View Dashboard →
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
