// CSRF Token Helpers
function getCsrfToken() {
    const csrfMeta = document.querySelector(
        'meta[name="csrf-token"]'
    );

    return csrfMeta
        ? csrfMeta.content
        : "";
}

function getJsonPostHeaders() {
    return {
        "Content-Type": "application/json",
        "X-CSRFToken": getCsrfToken()
    };
}

// Mobile Sidebar Navigation
const menuButton =
    document.getElementById("menuButton");

const sidebar =
    document.getElementById("sidebar");

const navigation =
    document.getElementById("navigation");

const sidebarBackdrop =
    document.getElementById("sidebarBackdrop");


function closeSidebar() {
    if (!sidebar) {
        return;
    }

    sidebar.classList.remove(
        "is-open"
    );

    if (sidebarBackdrop) {
        sidebarBackdrop.classList.remove(
            "is-open"
        );
    }

    if (menuButton) {
        menuButton.setAttribute(
            "aria-expanded",
            "false"
        );
    }

    document.body.classList.remove(
        "sidebar-open"
    );
}


function openSidebar() {
    if (!sidebar) {
        return;
    }

    sidebar.classList.add(
        "is-open"
    );

    if (sidebarBackdrop) {
        sidebarBackdrop.classList.add(
            "is-open"
        );
    }

    if (menuButton) {
        menuButton.setAttribute(
            "aria-expanded",
            "true"
        );
    }

    document.body.classList.add(
        "sidebar-open"
    );
}


if (
    menuButton &&
    sidebar
) {

    menuButton.addEventListener(
        "click",
        function () {

            const isOpen =
                sidebar.classList.contains(
                    "is-open"
                );

            if (isOpen) {
                closeSidebar();
            } else {
                openSidebar();
            }
        }
    );
}


if (sidebarBackdrop) {

    sidebarBackdrop.addEventListener(
        "click",
        closeSidebar
    );
}


if (navigation) {

    navigation
        .querySelectorAll("a")
        .forEach(
            function (link) {

                link.addEventListener(
                    "click",
                    function () {

                        if (
                            window.innerWidth <= 980
                        ) {
                            closeSidebar();
                        }
                    }
                );
            }
        );
}


document.addEventListener(
    "keydown",
    function (event) {

        if (
            event.key === "Escape"
        ) {
            closeSidebar();
        }
    }
);

// Password visibility toggle
document
    .querySelectorAll("[data-password-target]")
    .forEach((button) => {
        button.addEventListener("click", () => {
            const targetId = button.dataset.passwordTarget;
            const passwordInput = document.getElementById(targetId);

            if (!passwordInput) {
                return;
            }

            const isHidden = passwordInput.type === "password";

            passwordInput.type = isHidden
                ? "text"
                : "password";

            button.textContent = isHidden
                ? "Hide"
                : "Show";
        });
    });

// Flash message dismissals
document
    .querySelectorAll(".flash-close")
    .forEach((button) => {
        button.addEventListener("click", () => {
            const message = button.closest(".flash-message");

            if (message) {
                message.remove();
            }
        });
    });

// Confirm destructive form submissions without inline scripts.
document
    .querySelectorAll("form[data-confirm]")
    .forEach((form) => {
        form.addEventListener("submit", (event) => {
            const message = form.dataset.confirm;

            if (message && !window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

// QR Code file input display
const qrImageInput = document.getElementById("qr_image");
const selectedFileName = document.getElementById("selected-file-name");

if (qrImageInput && selectedFileName) {
    qrImageInput.addEventListener("change", () => {
        const selectedFile = qrImageInput.files[0];

        selectedFileName.textContent = selectedFile
            ? selectedFile.name
            : "No image selected";
    });
}

// Copy to clipboard buttons
document
    .querySelectorAll("[data-copy-text]")
    .forEach((button) => {
        button.addEventListener("click", async () => {
            const text = button.dataset.copyText;

            try {
                await navigator.clipboard.writeText(text);

                button.textContent = "Copied";

                window.setTimeout(() => {
                    button.textContent = "Copy";
                }, 1500);
            } catch (error) {
                button.textContent = "Copy failed";
            }
        });
    });

// AI Assistant, Scan Handler, and Password Tools
document.addEventListener("DOMContentLoaded", function () {
    const assistantForm = document.getElementById("assistantForm");
    const assistantInput = document.getElementById("assistantInput");
    const assistantChat = document.getElementById("assistantChat");
    const assistantSendButton = document.getElementById("assistantSendButton");

    function addChatMessage(message, sender) {
        if (!assistantChat) {
            return;
        }

        const messageElement = document.createElement("div");
        messageElement.classList.add("chat-message");

        if (sender === "user") {
            messageElement.classList.add("user-message");
        } else {
            messageElement.classList.add("assistant-message");
        }

        const avatar = document.createElement("div");
        avatar.classList.add("message-avatar");

        avatar.textContent =
            sender === "user"
                ? "You"
                : "AI";

        const content = document.createElement("div");
        content.classList.add("message-content");

        // Treat both user and model output as untrusted plain text.
        const paragraph = document.createElement("p");
        paragraph.textContent = message;
        content.appendChild(paragraph);

        messageElement.appendChild(avatar);
        messageElement.appendChild(content);

        assistantChat.appendChild(messageElement);
        assistantChat.scrollTop = assistantChat.scrollHeight;
    }

    async function sendAssistantMessage(message) {
        if (!message) {
            return;
        }

        addChatMessage(message, "user");

        if (assistantSendButton) {
            assistantSendButton.disabled = true;
            assistantSendButton.textContent = "Thinking...";
        }

        try {
            const response = await fetch("/assistant/message", {
                method: "POST",
                headers: getJsonPostHeaders(),
                body: JSON.stringify({ message: message })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error("Assistant server error:", errorText);
                throw new Error("Server returned " + response.status);
            }

            const data = await response.json();

            if (!data.reply) {
                throw new Error("No reply received.");
            }

            addChatMessage(data.reply, "assistant");
        } catch (error) {
            console.error("Assistant error:", error);
            addChatMessage(
                "The assistant could not process your request. Please check the server and try again.",
                "assistant"
            );
        } finally {
            if (assistantSendButton) {
                assistantSendButton.disabled = false;
                assistantSendButton.textContent = "Send";
            }
        }
    }

    if (assistantForm && assistantInput) {
        assistantForm.addEventListener("submit", function (event) {
            event.preventDefault();

            const message = assistantInput.value.trim();

            if (!message) {
                return;
            }

            assistantInput.value = "";
            sendAssistantMessage(message);
        });
    }

    if (assistantChat) {
        const storedExplanation = sessionStorage.getItem(
            "phishguard_scan_explanation"
        );

        if (storedExplanation) {
            sessionStorage.removeItem("phishguard_scan_explanation");
            addChatMessage(storedExplanation, "assistant");
        }
    }

    const suggestionButtons = document.querySelectorAll(".suggestion-button");

    suggestionButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            const question = button.getAttribute("data-question");

            if (!question) {
                return;
            }

            sendAssistantMessage(question);
        });
    });

    // Explain Scan Result Handler
    const explainScanButton = document.getElementById("explainScanButton");
    const scanResultData = document.getElementById("scanResultData");

    if (explainScanButton && scanResultData) {
        explainScanButton.addEventListener("click", async function () {
            let scanResult;

            try {
                scanResult = JSON.parse(scanResultData.textContent);
            } catch (error) {
                console.error("Could not read scan result:", error);
                return;
            }

            explainScanButton.disabled = true;
            explainScanButton.textContent = "Preparing Explanation...";

            try {
                const response = await fetch("/assistant/explain-scan", {
                    method: "POST",
                    headers: getJsonPostHeaders(),
                    body: JSON.stringify({ scan_result: scanResult })
                });

                if (!response.ok) {
                    throw new Error("Could not explain scan.");
                }

                const data = await response.json();

                sessionStorage.setItem("phishguard_scan_explanation", data.reply);
                window.location.href = "/assistant";
            } catch (error) {
                console.error(error);
                explainScanButton.disabled = false;
                explainScanButton.textContent = "Explain Result";
            }
        });
    }

    // Browser-only password generator
    const generatePasswordButton = document.getElementById("generatePasswordButton");
    const generatedPassword = document.getElementById("generatedPassword");
    const copyPasswordButton = document.getElementById("copyPasswordButton");
    const passwordLength = document.getElementById("passwordLength");
    const passwordLengthValue = document.getElementById("passwordLengthValue");

    if (passwordLength && passwordLengthValue) {
        passwordLength.addEventListener("input", function () {
            passwordLengthValue.textContent = passwordLength.value;
        });
    }

    function secureRandomIndex(maximum) {
        if (!window.crypto || !window.crypto.getRandomValues) {
            throw new Error(
                "Secure password generation is unavailable in this browser."
            );
        }

        const acceptedRange = Math.floor(256 / maximum) * maximum;
        const randomByte = new Uint8Array(1);

        do {
            window.crypto.getRandomValues(randomByte);
        } while (randomByte[0] >= acceptedRange);

        return randomByte[0] % maximum;
    }

    function secureChoice(characters) {
        return characters[secureRandomIndex(characters.length)];
    }

    function secureShuffle(characters) {
        for (let index = characters.length - 1; index > 0; index -= 1) {
            const randomIndex = secureRandomIndex(index + 1);
            const currentCharacter = characters[index];

            characters[index] = characters[randomIndex];
            characters[randomIndex] = currentCharacter;
        }

        return characters;
    }

    if (generatePasswordButton) {
        generatePasswordButton.addEventListener("click", function () {
            const errorElement = document.getElementById("generatorError");

            if (errorElement) {
                errorElement.textContent = "";
            }

            try {
                const ambiguousCharacters = "Il1O0o";
                const excludeAmbiguous =
                    document.getElementById("excludeAmbiguous")?.checked ?? false;

                const selectedGroups = [];

                if (document.getElementById("useUppercase")?.checked) {
                    selectedGroups.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                }

                if (document.getElementById("useLowercase")?.checked) {
                    selectedGroups.push("abcdefghijklmnopqrstuvwxyz");
                }

                if (document.getElementById("useNumbers")?.checked) {
                    selectedGroups.push("0123456789");
                }

                if (document.getElementById("useSymbols")?.checked) {
                    selectedGroups.push("!@#$%^&*()-_=+[]{}?");
                }

                if (selectedGroups.length === 0) {
                    throw new Error("Select at least one character group.");
                }

                const groups = selectedGroups.map(function (group) {
                    if (!excludeAmbiguous) {
                        return group;
                    }

                    return Array.from(group)
                        .filter(function (character) {
                            return !ambiguousCharacters.includes(character);
                        })
                        .join("");
                });

                const requestedLength = Number.parseInt(
                    passwordLength ? passwordLength.value : "18",
                    10
                );

                const length = Math.max(12, Math.min(requestedLength, 64));
                const combinedCharacters = groups.join("");
                const passwordCharacters = groups.map(secureChoice);

                while (passwordCharacters.length < length) {
                    passwordCharacters.push(
                        secureChoice(combinedCharacters)
                    );
                }

                if (generatedPassword) {
                    generatedPassword.value = secureShuffle(
                        passwordCharacters
                    ).join("");
                }
            } catch (error) {
                if (errorElement) {
                    errorElement.textContent = error.message;
                }
            }
        });
    }

    if (copyPasswordButton && generatedPassword) {
        copyPasswordButton.addEventListener("click", async function () {
            if (!generatedPassword.value) {
                return;
            }

            try {
                await navigator.clipboard.writeText(generatedPassword.value);

                copyPasswordButton.textContent = "Copied";

                setTimeout(function () {
                    copyPasswordButton.textContent = "Copy";
                }, 1200);
            } catch (error) {
                copyPasswordButton.textContent = "Copy failed";
            }
        });
    }
});
