What is Detection Engineering
Detection Engineering is the method of which logic, systems, and security controls are designed an implemented to detect and deter threats in a network to include the network devices, endpoint computers, data, applications, accounts and credentials. Detection Engineers are persons who research, emulate, test and deploy new controls through logic based rules to reduce risk and the Mean-Time-To-Detection (MTTD) so that the network and greater organization can carry out it's intended purpose.
General Tasks and Activities of a Detection Engineer
Translating intelligence into actionable detections with low noise
Evaluating data integrity and quality for detection opportunities
Identifying gaps in coverage and knowledge regarding threats and our capability to detect those threats
Developing tools and infrastructure to curate, test, deploy and maintain diverse detection-as-code content sets
Prioritizing detection opportunities in an attack-chain to optimize our response while reducing our resources and time spent on attempting to detect everything
Integrate and work with Open Source, commercial, and proprietary tools to build practical solutions to detection and response needs for the business
Communicate and partner with business departments to include Security Operations to prioritize detection strategies and goals
Provide value not by by the number of detections created/deployed but by the impact of our labor and how it reduces risk for the organization.
Detection Engineering Terms to Understand
Term
Meaning
Content
The end result of work in the form of a detector or rule. Content refers to more than logic, but the information about the detector, reasoning, justification, and what the detector does.
Noise
Computers are noisy and sometimes a detector or the result of a detector "firing" can create a lot of low quality or low confidence results i.e. noise
Confidence
A measure of how reliable a specific detector usually is with respect to it's performance i.e. True Positive vs False Positive rate. This is based on historical performance or the uniqueness of the matching logic with respect to the threat.
MTTD
Mean-Time-To-Detection is the measure of the mean time between the event occurring and the detection firing. This can also relate to the mean time to the recognition of a valid threat on the system.
MTTR
Mean-Time-To-Respond is the measure of the mean time between a detector identifying a threat and the response to that event.
Detector
A rule or logic written down that is used as a method to compare an input for matching purposes. If the match is true, the result could indicate malicious or at least suspicious activity.
Efficacy
Another nomenclature for "confidence" but is the measure of Accuracy and Precision and can be representing in a whole number, percentile, or label such as low, medium, high etc.
Accuracy
How close a detector is to identifying the inteded match condition. A detector with low accuracy produces "noise" or "too many false positives"
Precision
A measure of how consistent a detector is to matching the intended event. A low accuracy, high precision detector is good at making noise. A high accuracy/precision detector has creates high confidence in its ability to find evil.
Data Quality
The ability to create "good" detectors is correlated to the quality of the data. What's in the data, how it is presented, formatted etc. directly dictates how agile the detection engineer can be with our detection logic.
Data Integrity
Confidence in that the information remains accurate, consistent, and unaltered during storage, transmission, and processing.
Knowledge Gap
The awareness to know what you don't know about a threat, system, technology, process, or procedure. This gap analysis provides an assessment of risk that allows for the targeted research to close these gaps in knowledge.
Coverage Gap
Refers to the areas of the network not under coverage i.e. "that server has no coverage and we don't know what's happening there"
Visibility Gap
An asset that has coverage has some form of visibility, but we may not see everything on a system. We have visibility gaps within our covered assets.
MITRE ATT&CK
A knowledge base of adversary Tactics, Techniques, and Procedures.
Tactic
Overarching goal of an adversary in their activity such as "Persistence" or their ability to persist on a compromised computer.
Technique
The method or approach to enable the above tactic. On any give system, there may be numerous ways to accomplish a goal.
Procedure
The detailed steps, tools, and process used to execute the technique

An axiom is a fundamental principle or statement that is accepted as true without requiring proof, serving as a starting point for further reasoning or argument. In mathematics and logic, axioms are the foundational assumptions from which other truths are derived. 

My Personal Hot-Takes for Detection Engineering
These are some nuggets of experience, philosophy, and perhaps an axiom or two on my personal growth in Detection Engineering. I hope these and the community resources above will help provide some wisdom during your Detection Engineering journey.
Consumers of detections will suppress and ignore detections if they do not understand the intent of the detection.
Ignored or suppressed detections destroy the critical feedback loop used to improve those detections.
You will push a rule that will break something. Regardless of the controls, training, process, and planning. It will happen.
A failure to quickly revert a change will damage your team's reputation much faster than the original break/issue. Plan and train for the worst.
The biggest failures in your work are usually due to a mundane or simple mistakes. Take it slow and don't overcomplicate things.
If you use REGEX without understanding the data, format, and scope - you will learn the latter things the hard way.
The fastest way to fail is trying to detect all the things. Find the commonality in your risk and attack there.
Identifying detection opportunities that were missed during an incident is normal. Don't take it personally. Work the problem.
Detection Engineering is a black box to others. Communication and education to other departments is as important as any other detection task.
Process and Documentation are our weapons of choice. If you don't document what you know vs don't, you will never mature as a team.
Importance of Good Documentation
A key factor in a mature Detection Engineering program is documentation. It's often neglected and overlooked in the rush to get effective detections live and working to protect the organization. The fact that the job of a detection engineer is very fast-paced, as malware and threat actors change tactics and techniques daily at times. The battle is unending, so moving quickly is important to keep from falling too far behind (most programs will always be behind the game in some aspect--it is nearly impossible to get ahead or predict the next thing that will need detection). Despite this fact, documentation is still important. Good documentation will lead to better detection strategy overall. If you can clearly document both your process and the detections themselves, they will likely be more thorough and complete as well easier to understand and follow.
Process Documentation
There are endless methods and application that can provide an adequate system for documentation. Anything from basic word documents to markdown or basic text files in a shared location can do the job. A webapp made specifically for documentation is a great choice to make the process easier and more streamlined. Some choices here include Confluence, Drupal, Jive, ClickUp, HelpJuice, Nuclino, or even SharePoint. But any place to easily create, store, edit, and access a set of shared documents will suffice. As long as you can write down the process you intend to follow so others can understand and follow the same process, that is all you need.
Detection Documentation
While many forms or systems of detection-as-code can be somewhat self-documenting, they typically will not allow or require the kind of in-depth documentation that will be most helpful. More importantly, most common methods or rule formats (like Sigma or YARA) do not allow the kind of flexibility to be able to add different sections to the rule in formats that are useful and conducive to good documentation. The format is not meant for reading and comprehension as much as it is meant for storing data that will be interpreted as code by a detection engine software program of some kind. This means that this kind of data is not meant to be easily read and understood by humans, and does not allow for storing data in this kind of format. If the detection rules themselves are not the best place for full documentation, what is a better option?
ADS Framework
As the cybersecurity industry has matured and grown, more tools and frameworks are created by practitioners to help make doing the job easier. One such tool was created by Palantir, as they found themselves in need of a more structured method for creating and documenting their detections and alerts. They created the Alerting and Detection Strategy Framework (ADS). A full explanation of ADS can be found on their website ADS contains the following sections:
Goal
Categorization
Strategy Abstract
Technical Context
Blind Spots and Assumptions
False Positives
Validation
Priority
Response
Each of these sections helps to clarify and direct detector creation. In their system, no detection can be used until each section is complete. This means that each detection will be well-thought out, as completing the sections requires careful thought and clear understanding of the goal and method of the specific detection. By having a formal way to structure and document these ideas, any analyst or engineer can easily come back to the detection and make changes later as needed and understand the intent of the rule when trying to investigate an alert. This can lead to fewer false positives. Let's look at an example.
Palantir provides some example cases--let's look at the osquery MacOS Malware Detection example. This is supposed to match known malware names and paths, found in osquery signature packs. However, when investigating an alert it might not be clear how the logic works and what could lead to a false positive. Reading the ADS documentation for this alert can make it more clear:

# Blind Spots and Assumptions

This strategy relies on the following assumptions:

* Osquery is running on hosts.
* Osquery has the correct query packs.
* Osquery is successfully reporting data to the Kolide endpoint.

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:

* Osquery stops running or is tampered with.
* The malware sample does not match an entry in the osx-attacks query pack.

Note: This detection method is only able to detect known malware using static indicators. Malware variants may not be picked up by osquery.

# False Positives

There are very limited instances where false positives will occur:

* A legitimate file uses the same filename or filepath as a malicious sample.
* A legitimate file is accidentally added to the osx-attacks query pack.

Note: No false positives were detected during staging or production. It is extremely unlikely that a false positive will occur on this ADS.



Here we can see two key factors:
It's assumed osquery is running on the host.
The detection is based on static file names and paths, which could have collisions with legitimate files.
Now we know that if osquery is not running, we should not expect to see this alert. And we need to investigate the file to see if there similarities with known MacOS malware that is part of the osquery signature pack. If the file does not look at these known malicious files, and has some indication that it could be something legitimate, then we need to be more cautious before sending this alert as a true positive. Without the ADS documentation, we would not know what to look for in potential false positives and the triage process would likely take much longer.
Indicator vs Behavior
Indicator: An indicator refers to a specific piece of evidence or artifact (such as a file hash, IP address, or network traffic pattern) that suggests suspicious or malicious activity, often used to identify or confirm an attack or breach.
Behavior: A behavior refers to the observable actions or patterns of activity that are characteristic of adversarial activity, such as unusual login attempts, lateral movement, or privilege escalation, which are used to identify potential threats based on their operational characteristics rather than specific indicators.
Fragile Vs. Resilient
As we write detections, we will make use of various datapoints and with respect to our research and experience, will have an inherent confidence and expectation of that rule. It is important to know however that how we rely on data directly relates to how fragile the rule is or how resilient to variations or change it is.
What is meant by that is what type of match parameters are used in the detector? Indicators as described above as single or atomic in nature, such as an IP address. If we craft a rule reliant on primarily atomic indicators, that rule in essence is very fragile to change and has a short shelf life. It is fragile and is not resilient to deviations of the technique or procedure employed by the adversary.
Indicator Example



A large portion of network intelligence and detection consist of lists that include a supposed malicious IP and may include port or domain information.

Hopefully it is obvious that using strictly atomic indicators is the path down a life of whack-a-mole. I will however contradict myself and say there is certainly a time and place for such indicators in our detections.
A new CVE or 0-Day is identified an initial indicators are the adversaries infrastructure indicators such as IP. This may be all we have to detect this threat. Just know, that is a matter of hours and maybe days before this detector is no longer valid as the cost of changing IPs is near trivial for an adversary.
The IP belongs to a well-known entity that is of high risk i.e. A Russian network block that is consistently observed conducting computer attacks. The business could asses the risk A) We don't have customers there B) Even if we did, the risk is too great. We could detect or outright block any connection from those IP addresses.
There are of course more reasons to do this, but many of those reasons are organizational and dependent on that organization' risk tolerance.
Behavior Example


If we take note of the detection block and it's subsequent selector blocks, we can see the logic encoded within this detector. We can review known LOLBAS or Living and the Land Binaries and Scripts to get some more information on this technique and the detector itself
LOLBAS are native windows tools or features that are and can be exploited by an adversary to enable a Tactic. Instead of bringing their own malware, adversaries have learned to use the system as is. This makes detection and response efforts harder as the activity appears "legitimate" in many cases, but not always. 


CertUtil can be used for numerous things and as you would expect, it's a utility for working with certificates on Windows. This rule is behavioral as it is looking and matching a tactic/procedure i.e. it's detection and activity that is doing something: DOWNLOADING. It's a unique and well known binary that is signed by Microsoft. So we can validate the binary or process is the one we expect and can look for the download behavior. The challenge with this detector long term is that there are software vendors and admins who use this LOLBAS technique to accomplish legitimate network administration tasks.
Correlation of Detections
Working with each detection individually is time consuming from a triage and response perspective. SIEMS and other technologies are used to evaluate risk for an entity based on the cumulative detections over an observable time window.
Taking the two example above, it would require work to determine if the detections individually are True Positive and worth the time for review, considering the hundreds to thousands of other detections a network could have in a single day (dependent on the size of the organization).
However, what if a new detection was created dynamically that consisted of:
Host: ABC-Windows
User: Bob
Detections: 2
Detected Events: Suspicious Download, Malicious IP Address

Hopefully you see that detections regardless of type, can be used to develop a narrative around a host and series of events. To save time and enable our Security Operations teams to triage and respond faster, we need to think about how we write, plan, and execute our detection efforts. We need to keep the consumer of these detection in mind and how they use them should be considered when creating them.
True/False Positive/Negative
If you've done Detection Engineering in the past or are just starting out, False Positives will be the bane of your existence. Not inherently due to bad detectors, code, collection/data issues, weird and unexpected apps etc. Those will all happen, but what is not discussed as much is the misinterpretation of what constitutes a False-Positive from those who aren't Detection Engineers. Remember when I said our roles required us to be educators and proactive in our outreach...
What we mean by this is that the intention of a detector will not always be to find malicious activity. In my role and team, we have low priority detectors that provide low to informational context. If you recall from earlier, I believe its the job of a good DE strategy/team to provide context and narrative to a noisy problem. Sometimes, we need detectors that define a behavior for the sake of awareness.
In those instances, some may view the output of that detector as a False Positive in that it did not find maliciousness. Again, not always the goal. This illustrates a key issue in education and documentation where anyone who consumes the detection should be able to discern the reasoning, scope, and intent of the detection.
A key question I would ask someone who is pushing back on these informational detection is this: "Would you rather analyze 100,000 raw logs or look at 100 detections grouped by the entity they are tied to?" . In most, not all cases, it is much easier to quickly assess 100 items vs 100k to discern malicious intent, severity, and priority of our containment and response needs.
Differentiate Classification and Truth
By design a detector uses various methods and logic to inspect an event and attempt to classify the event. Fundamentally, the detector evaluates if the event is a positive or negative match.
Positive: The event matches the rule logic
Negative: The event does not match the rule logic
While we expect that every detection was written with the best intent and tested thoroughly, there certainly exists where classification failed to accurately assess the observed event. Primarily done through human-aided triage, each detection or signal is reviewed and prioritized accordingly to risk. Through this function, a determination will occur to identify if the detection was True or False in it's initial classification.
True: The detection is a valid case and warrants further triage/engagement.
False: The detection is not valid and does not warrant further triage/engagement.
A simple way to think about this is that we have two parties. The Detection Engineering team who creates a detector that attempts to classify something as a match. We then have the Security Operations team who looks at the result and confirms if we are true or false in our assessment. It is critical to have a feedback loop in this process so we can learn from negative assessments and improve our process and procedures to matching our intended use-cases.
Truth Matrix for Detection Engineering
Truth Type
Meaning
Example
True Positive
The detector classified this event as a positive match and review confirmed it was a true claim
The detection positively identified the use of Mimikatz on a server.
False Positive
The detector classified this event as a positive match and review confirmed it was a false claim
The detector alerted us to an administrative script that downloaded legitimate software.
False Negative
The detector classified this event as a negative match and review confirmed it was a false claim
A Threat Hunter on the team alerted us to an incident we did not generate any alerts for. We missed that one.
Extended Classification and Understand
These are the foundational Classification and Truth tables we would use to generally describe the efficacy of a detection. How often does it claim a positive event that turns out true? If it's frequent, we can have a high confidence in that detection and prioritize our response when it matches an event.
Beyond these simple conditions, we can extend classification and include other metadata to our detections. Some things to consider when adding context to your rules when evaluated help both the detection team and your internal intelligence efforts to contextualize and learn from observed trends in your detections.
What type of a true positive event? Pentest, Informational event, Known malware, 0-day, Open Source Hacktool, ransomware...
Is the True Positive benign, malicious, or just suspicious?
What type of false positive? Didn't match the intended event, Poorly written rule, adversary tactics changed, OS no longer vulnerable
These are just some questions we've asked ourselves when looking at your TP/FP events and tried to understand where we could improve. Dependent on the organization you work for, and what you have coverage on, it won't be long before you recognize that you need enhanced classification contexts to better baseline your effort and identify changes in trends.
A Quick Read
Here is an external blog that provides some additional context to this topic of understanding the narrative around False Positives. Revisiting the Idea of the "False Positive" by Joe Slowik



The Pyramid of Pain is concept that's been around since 2013. David Bianco created this concept to demonstrate "the relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them." The point was in help defenders be more efficient and more effective in the kinds of indicators used to detect malicious behaviors. By focusing on things that cause the most pain for adversaries, you increase your chances for sustained success detecting it. Conversely, by chasing trivial indicators such as IP addresses, you often find yourself on the losing end, as IPs are easy and cheap to change. While they can be effective at times in detecting a particular adversary over time, most often these are not very useful other than for a short period of time. This means that defenders would have to change their detections often if they are relying on quickly changing indicators such as IP addresses. So it is typically a better idea to focus on things that are less likely to change. Bianco puts TTP's at the top of the pyramid, because these are the methods in which adversaries carry out attacks and they are much less likely to change these over time.
http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
Bianco was certainly right about this, however his original Pyramid of Pain did not separate TTPs into categories and made it seem like tactics, techniques, and procedures are all of the same value as indicators or cause the same amount of pain. This is not the case.
In 2022, Christopher Peacock published a blog for Scythe in which he detailed the differences between these three, highlighting the importance of focusing on the "toughest" of these three as well. While a tactic used in attack can be quite broad (such as Credential Access) and more universal, techniques are more specific to the attack (method of Credential Access) and the procedure is even more specific to the tool or command used to get Credential Access. Focusing on the procedures used is far more accurate and causes more pain. If you detect an attack based on commands or API calls used by Mimkatz to dump credentials, this will typically provide more value than grouping all Credential Access methods together. This extension to the original Pyramid of Pain provides more granularity and clarity to the concept.

In 2023, Mitre Engenuity released a new project called Summiting the Pyramid This is another extension on the original pyramid.

This project sets out to evaluate, measure, and score the effectiveness of detection rules based on the principles of the Pyramid of Pain. The project also demonstrates how to further analyze any indicator and work toward detecting the underlying OS functions and operations that are used in an indicator as well as evaluating how reliant a certain detection method is on a tool with the goal of trying to find behaviors that are "core to the sub-technique" being used as opposed to relying on more ephemeral or transient indicators. This projects gets quite in depth on this concept and is beyond the scope of this course. Awareness of this project and the concepts discussed in it provide a wealth of very applicable knowledge that can improve any detection engineering program that uses it. We highly recommend reading further on these concepts once you have a solid understanding on the fundamentals.
For a great summary of the Summiting the Pyramid project, check out What is the Pyramid of Pain? by Picus Security.
All of the concepts introduced in this section have one main point--it is important to consider more than just CAN you detect something using any given method or logic, but is this the best method? Is this the only method? What assumptions are being made with this method? What type of false positives or false negatives may occur? How easily can this detection method be evaded? While answering these questions may not change the decision to use a method in the end, but you should always be aware of these things and if possible account for them in some way in order to be most effective in your detection strategy.

