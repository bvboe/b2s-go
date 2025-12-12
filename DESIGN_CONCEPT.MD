Goals of the project:
We're making a reimplementation of https://github.com/bvboe/bjorn2scan/. Bjorn2Scan served as a great proof of concept
that proved out the following concepts:
* It's possible to scan containers on the host they're running wihout downloading them from the source repository
* It's possible to track what workloads are running on the Kubernetes cluster and keep the scan data up to date
* It's possible to apply a similar scanning approach to the hosts themselves
* There's a ton of value in aggregating the data and using OpenTelemetry to share the data with Prometheus / Grafana
* The combination of Syft and Grype was particularly valuable for collecting the SBOM, storing it and
  analyzing it on a regular basis.
* The web UI was simple, but very effective
* We've learned a lot about how ContainerD and Docker works under the hood
* Helm works great for deploying to Kubernetes

The approach also had some weaknesses:
* The choice of usig Python as a programming language enabled rapid development, but also had some big
  limitations
* No unit testing made some designs feel like trial and error, and the integration testing is limited
* We ran into performance limitations for large datasets
* Aggregation of data was tricky
* The integration between vulnerability coordinator and scanners felt kind of flimsy, but it worked(!)
* We don't know how well this approach scales in larger clusters
* Security is not a first class citizen

We'll therefore do a complete reimplementation where we'll take the lessons learned and do it in a better way. We do
not just copy things from the old implementation. We build this gradually and reassess all implementation choices
to make sure it's working according to our requirements. This among others means the following will be important:
* We will be build two kinds of scanners: One to be deployed on a Kubernetes cluster, similar to what version I did.
  We'll also do an agent based implementation that is to be deployed directly on a host, scan the host itself
  and whatever containers that are running on the host.
* We'll be building the application using Go. The code needs to be modular, so that the same code can go into the
  Kubernetes scanner, as well as the agent scanner, even though the way they will be deployed is completely different.
* Testing is important. We'll be using test driven development whenever it makes sense, and integration testing.
* Proper CI/CD and release management is important from day 1.
* It's important to have a securely defined deployment
* Enable reuse of code, and externalize configuration whenever needed. We don't duplicate code. Ever!
* Developer productivity is key. We'll have a challenge as the developer desktop is on macOS, while the application
  will be running on Linux based containers / hosts. The applications will be very dependent on the environment
  they get deployed into, so containers will be very useful for supporting the development environment. We'll
  also need scripts to support rapid local deployment.
* We'll be leveraging Kind and MiniKube for testing locally on the desktop, as well as for integration testing.
* Whatever testing we'll be doing in the CI/CD pipeline should also be executable from a developer desktop.
* Whatever containers we're building will be using Wolfi.
* Use sigstore to sign build artefacts
* The web UI will be served as static html, supported by css and JavaScript. This means we have the choice between 
  using nginx to serve the pages or have the go application do the work.
* We'll need to support ARM64 and AMD64 based hardware.
* Given that we're building a scanner to look for software vulnerabilities, it's important that we keep our own
  infrastructure in order, and ship software with as few CVEs as possible. The Wolfi images are going to help
  but it also means keeping dependencies up-to-date is important, and we only hold off on upgrading dependencies
  if it introduces new vulnerabilities.

Project Context and Scope:
* This is bjorn2scan v2 - a continuation and evolution of the original project.
* Development will start in a separate GitHub repository, with the goal of eventually moving it over to the main
  bjorn2scan repository and retiring the old code in a separate branch.
* The project will use the same open source license as v1.
* Target audience is broad (developers, DevOps engineers, security teams), but the primary users are expected to
  be security professionals.
* Success criteria:
  - First milestone: Good enough for use in a personal lab environment (multiple servers, Kubernetes clusters)
  - Longer term goal: Make it useful and robust enough for enterprise settings
* This is a solo project.
* Documentation and getting started guides are crucial and should be prioritized from day 1.
* The transition from v1 to v2 will be figured out over time. Preserving Helm compatibility would make transitions
  easier, but it's optional - it's acceptable to completely remove v1 before deploying v2 if needed.

A few important notes wrt the relationship between human and AI.
* Don't assume, ask!
* Don't try to build it all at the same time. There's a lot we don't know, and there are a lot of thigns
  to be figured out. That means it's important to build the system in small increments.
* If I ask for options or recommendations for how to solve a problem. Give me the options. Do not just go ahead
  and implement it. I should not have to yell STOP!
* Be concise and to the point. No need to brag about how smart I am.
