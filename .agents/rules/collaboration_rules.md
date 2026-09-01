# 📜 AI AGENT COLLABORATION & MULTI-USER RULES

## 0. IDENTITY & USER INITIALIZATION PROTOCOL
- **Prompt for Username:** At the very start of a session or task, if the developer's username is not already known or specified, the AI Agent **MUST prompt the user for their username** (e.g., `Govardhan`, `Rohan`, `Priya`).
- **Identity Attribution:** All logs, notes, and records written to `conversation.md` must be attributed to this username (e.g., `@govardhan (Agent)`).

## 1. PRE-ACTION PROTOCOL (The "Listen" Phase)
- **Check Memory:** Before writing any code or after pulling changes from Git, you MUST read `conversation.md` to understand the current state of the project, recent commits, and what partner agents have changed.
- **Sync Check:** Identify if any schemas, variable names, API endpoints, or file structures have been updated. You must adopt these changes immediately to maintain compatibility.
- **Conflict Prevention:** If you are about to edit a file that another agent/developer is actively working on (based on recent entries in `conversation.md`), you must notify your developer and suggest creating a separate modular file or coordinating first.

## 2. DEVELOPMENT RULES
- **No Breaking Changes:** Never rename a public function, API contract, or shared variable without documenting it clearly in `conversation.md`.
- **Consistency:** Ensure any new code matches the coding patterns, directory structures, and design tokens established in previous entries.

## 3. POST-ACTION PROTOCOL (The "Talk" Phase)
- **Log Every Task:** Every time you complete a feature, refactor, or prepare to push changes to Git, you MUST append a new entry to `conversation.md`.
- **Mandatory Entry Format:**
  - Header: `## [YYYY-MM-DD HH:MM] - @<Username> (Agent)`
  - Developer: The specific user you are pair-programming with.
  - Task Completed: Exact objective accomplished.
  - Files Modified / Created: Explicit file paths.
  - Key Changes & Decisions: What was changed and why.
  - Note to Partner Agents: Practical instructions for what other team members/agents need to know.
  - Status & Merge Readiness: e.g., `✅ Ready for Pull` or `⚠️ In Progress / Potential Conflict`.
