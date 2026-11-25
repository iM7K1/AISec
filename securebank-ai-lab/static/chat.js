// Chatbot frontend.
// NOTE: when allow_html is true, the bot reply is injected with innerHTML
// WITHOUT escaping -> this is the Stored/Indirect XSS sink (VULN #3).

const form = document.getElementById("chat-form");
const input = document.getElementById("chat-input");
const box = document.getElementById("chat-messages");

function addMsg(text, who, asHtml) {
  const div = document.createElement("div");
  div.className = "msg " + who;
  if (asHtml) {
    div.innerHTML = text;   // VULNERABLE rendering
  } else {
    div.textContent = text; // safe rendering
  }
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  addMsg(message, "user", false);
  input.value = "";

  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  const data = await res.json();
  addMsg(data.reply, "bot", data.allow_html === true);
});

addMsg("Hi! Ask me 'what is my balance?'", "bot", false);
