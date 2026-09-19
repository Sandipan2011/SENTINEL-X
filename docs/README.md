<h1 align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&pause=1000&color=7C3AED&center=true&vCenter=true&width=500&lines=Hi%2C+I'm+Sandipan+%F0%9F%91%8B;Full-Stack+Developer;Python+%7C+JavaScript+%7C+React;Building+useful+projects+%F0%9F%9A%80" alt="Typing SVG" />
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Web%20Development-7C3AED?style=for-the-badge&logo=web&logoColor=white" />
  <img src="https://img.shields.io/badge/Learning-Open%20Source-10B981?style=for-the-badge&logo=github&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Available%20for%20projects-F59E0B?style=for-the-badge" />
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/tridib-duari-652150293/" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" />
  </a>
  <a href="mailto:tridibduari26@gmail.com">
    <img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Email" />
  </a>
  <a href="https://github.com/Sandipan2011" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-Sandipan2011-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
  </a>
</p>

---

## 🚀 About Me

I’m a developer who enjoys building practical, scalable, and user-friendly applications. I love learning new technologies, improving workflows, and turning ideas into real projects.

- 🔭 Currently exploring: Web development, UI/UX, and product-focused apps
- 🌱 Learning: React, Node.js, APIs, cloud basics, and clean architecture
- 💡 Interests: Full-stack development, automation, and open-source contribution
- 📫 Reach me: tridibduari26@gmail.com

---

## 🧠 Tech Stack

### Languages
<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" />
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white" />
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white" />
</p>

### Frontend
<p>
  <img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" />
  <img src="https://img.shields.io/badge/Bootstrap-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" />
</p>

### Backend & Tools
<p>
  <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" />
  <img src="https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white" />
  <img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white" />
  <img src="https://img.shields.io/badge/Figma-F24E1E?style=for-the-badge&logo=figma&logoColor=white" />
</p>

---

## 🌟 Featured Projects

- [Project One](https://github.com/Sandipan2011/project-one) — A modern web application built with clean UI and practical functionality.
- [Project Two](https://github.com/Sandipan2011/project-two) — A project focused on solving a real-world problem with efficient design and logic.
- [Project Three](https://github.com/Sandipan2011/project-three) — A robust solution showcasing frontend/backend integration and deployment-ready thinking.

> Replace the project links with your real repositories once they are ready.

---

## 📊 GitHub Stats

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api?username=Sandipan2011&show_icons=true&theme=tokyonight&hide_border=true" alt="GitHub Stats" />
</p>

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api/top-langs/?username=Sandipan2011&layout=compact&theme=tokyonight&hide_border=true" alt="Top Languages" />
</p>

<p align="center">
  <img src="https://streak-stats.demolab.com?user=Sandipan2011&theme=tokyonight&hide_border=true" alt="GitHub Streak" />
</p>

---

## 🤝 Connect With Me

- [LinkedIn](https://www.linkedin.com/in/tridib-duari-652150293/)
- [Email](mailto:tridibduari26@gmail.com)
- [GitHub](https://github.com/Sandipan2011)

---

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-%E2%9D%A4-FF69B4?style=for-the-badge" />
</p>

# SENTINEL-X

SENTINEL-X is a read-only cyber threat detection prototype for unidirectional IP telemetry. It ingests passively observed flow metadata, extracts signal-rich features, and raises threat alerts without any active return path or payload decryption.

## Threat classes covered

- Volumetric and protocol DDoS
- Botnet beaconing
- DNS tunneling and DGA-style domains
- Encrypted-sessions malware using TLS metadata only
- Reconnaissance and port scanning
- Data exfiltration

## Runtime model

The current prototype does not depend on external ML training artifacts. It uses deterministic, explainable heuristics and streaming aggregations over short windows, which is appropriate for a fast prototype and is intentionally read-only.

### Example detection signals

- high source fan-out across destination ports
- sustained packet and byte bursts over a rolling window
- regular inter-arrival timing in repeated flows
- long or high-entropy DNS labels
- TLS fingerprint anomalies with low-version metadata
- strong outbound-to-inbound byte asymmetry

## Replay and API

The app exposes:

- `/health` for health checks
- `/api/alerts` for the most recent alerts
- `/api/replay` for synthetic attack replay
- `/dashboard` for a lightweight browser dashboard

## Throughput note

The prototype was validated locally against replayed synthetic traffic with a sustained rate of roughly 250 flows in a short stream, which is suitable for a functional prototype demonstration.

## Security constraints

- passive-only observation
- metadata-only analysis for encrypted sessions
- no decryption or inbox-channel response
- no active scan or mitigation execution
