# Disclaimer

## Security Research and Defensive Testing

ZIPBomb is a security research and defensive testing tool designed to generate, analyze, and safely process pathological ZIP archives.

The project is intended for legitimate security testing, development, research, and validation of systems that accept or process untrusted archives.

Examples of appropriate uses include:

* Testing your own applications and infrastructure.
* Testing archive extraction limits.
* Testing web crawlers and document-processing pipelines.
* Developing ZIP-bomb detection and mitigation mechanisms.
* Creating reproducible security test fixtures.
* Performing authorized security assessments.

## Authorization

You are responsible for ensuring that you have permission to test any system, service, application, network, or infrastructure against which ZIPBomb-generated archives are used.

Do not use this software to intentionally exhaust, disrupt, degrade, or interfere with systems that you do not own or have explicit authorization to test.

The fact that a system is publicly accessible does not constitute authorization to conduct resource-exhaustion testing against it.

## Resource Exhaustion

Pathological archives can cause significant CPU, memory, storage, or I/O consumption when processed by vulnerable software.

Even a test performed with defensive intentions can unintentionally cause:

* Disk exhaustion.
* Memory exhaustion.
* Excessive CPU utilization.
* Application crashes.
* Service degradation.
* Denial of service.
* System instability.

Always use controlled environments and explicit resource limits when testing.

ZIPBomb provides safety mechanisms for controlled generation and extraction, but these mechanisms do not guarantee that every downstream archive implementation will behave safely.

## Third-Party Software

ZIPBomb does not guarantee the behavior, security, or resource consumption characteristics of third-party ZIP parsers, archive extractors, crawlers, antivirus products, document processors, or other software.

Different implementations may handle pathological archives differently.

Testing should therefore be performed in isolated environments with appropriate resource controls.

## No Warranty

This software is provided **"as is"**, without warranty of any kind, express or implied.

The authors and contributors are not responsible for:

* Damage caused by generated archives.
* Data loss.
* Service interruptions.
* System crashes.
* Resource exhaustion.
* Security incidents.
* Misuse of the software.
* Damage caused by third-party archive-processing software.

Use the software at your own risk.

## Responsible Disclosure

If testing reveals a vulnerability in third-party software, follow responsible disclosure practices.

Provide the affected vendor with sufficient technical information to reproduce and remediate the issue while avoiding unnecessary disruption to production systems.

## Final Notice

**Only use ZIPBomb against systems and environments you own or are explicitly authorized to test.**

The purpose of this project is to improve the resilience of software against malicious or pathological archives, not to disrupt systems belonging to others.
