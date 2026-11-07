# PlutoHacks-Zero-Day
PlutoHacks Submission 2026: Build, Protect, Innovate

To use this project, place the entire repo into a folder. Go to chrome://extensions and turn on developer tools, then select the option labelled "Load Unpacked." That will allow you to host the extension through your browser.

**## AI Usage**
Our team used generative AI during our creation process to save time when building our prompts and our extension's backend. We used Google Gemini to pressure-test and question our initial Claude prompt. We used Claude AI to generate the base extension features, but we planned out the UI and drafted the logo by hand so that it matched our exact specifications. We configured text styling through CSS and configured API connections (we used a Gemini API connection to process web pages during scans) and some internal logic using JavaScript. While AI played a large role in the process of building our project's code, we fine tuned and customized to make it our own until the project matched our vision.

## Inspiration
When we heard the prompt about AI in cybersecurity, and the "Build, Protect, Innovate" message on the walls and on our shirts, we began thinking of who needed our creativity to protect them the most. The average internet user is surrounded by threats that they sometimes don't notice until it is too late, and having all experienced malware mishaps ourselves, we wanted to create a free and accessible tool to combat the explosion of cyber attacks across the internet.

## What it does
Our project is a chrome extension that will scan the HTML on any page that a user has on their screen, looking for security concerns and risk factors. When the user pulls up the extension to run a scan of the web page, an AI agent returns a synopsis of all risks and action items for the user to keep in mind while browsing on a particular website. The extension will also provide live news reports on recent cybersecurity breaches and incidents, giving non-technical action items so that users can protect themselves from similar threats on day zero. Finally, the extension allows users to post incident reports and concerns in a forum that will be interpreted by the AI to target the kinds of warnings and alerts that are most relevant to its users.

## How we built it
We used Claude AI to build a strong code base for a project, completing the extension's functionality with the help of automated coding agents to allow us to spend the majority of our time fine tuning and customizing our extension to best serve the target audience. We then went into the code to adjust CSS styling and fonts and to hook up an API connection to Google Gemini, which we used to process HTML information from each page the user scans. We designed UI structure and some of the graphics and the logo using pencil and paper, translating it to the computer and inputting it into the project afterwards. The rest of our time was spent testing and fine tuning features until they matched our vision, adjusting values and fixing bugs until the program ran smoothly.

## Challenges we ran into
One challenge we ran into was the difficulty we had learning JavaScript and CSS, entirely new languages to most of us, while creating a tool that solely runs on these languages. Although our background in C++ and python meant we were not total beginners, it was a tough learning curve, and it took time to work with these languages to get the output we wanted. 

## Accomplishments that we're proud of
We are immensely proud of how seamlessly our extension blends into the browser and how easy it is to use. When conducting demos with fellow hackers, we found that they were most impressed with how easy and simple it was to use, while still being a powerful and practical way to stay safe online. This ease of use that retains robust usefulness is our greatest achievement, and was our primary goal when making the project.

## What we learned
We learned a metric ton about JavaScript, CSS, and Chrome Developer Tools. We learned about the powerful benefits and the pitfalls of using generative AI, both losing and gaining time by integrating it into our creation process. We also grasped the importance of planning and organization when working on a team, as the hours we spent brainstorming and planning allowed our actual building process to go much more quickly than it would if we did not have a clear idea of where we were going or who was delegated to what task. Everything starts with a good idea, and our priority above all else was making sure that once we found one, it could be showcased to its full potential.

## What's next for Zero Day
This extension has the potential to be a genuinely useful tool for people of all ages and backgrounds on the internet, and we will be using it ourselves to protect ourselves when browsing and attain a level of peace of mind that is difficult in a time of online paranoia and evolving threats. We will also explore the Chrome Web Store as a way to put this tool into the hands of the public for free.

