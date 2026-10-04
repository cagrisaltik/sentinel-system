const form = document.getElementById("loginForm");
const card = document.getElementById("loginCard");
const errorMessage = document.getElementById("errorMsg");
const submitButton = form.querySelector("button[type=submit]");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const originalText = submitButton.textContent;
    submitButton.textContent = "AUTHENTICATING...";
    submitButton.classList.add("is-loading");
    errorMessage.classList.remove("is-visible");

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: document.getElementById("username").value,
                password: document.getElementById("password").value
            })
        });
        if (!response.ok) {
            throw new Error("Login failed");
        }
        submitButton.textContent = "ACCESS GRANTED";
        submitButton.classList.remove("is-loading");
        submitButton.classList.add("is-success");
        window.setTimeout(() => { window.location.assign("/"); }, 500);
    } catch (_) {
        submitButton.textContent = "ACCESS DENIED";
        submitButton.classList.remove("is-loading");
        submitButton.classList.add("is-error");
        errorMessage.classList.add("is-visible");
        card.classList.add("shake");
        window.setTimeout(() => {
            submitButton.textContent = originalText;
            submitButton.classList.remove("is-error");
            card.classList.remove("shake");
        }, 1500);
    }
});
