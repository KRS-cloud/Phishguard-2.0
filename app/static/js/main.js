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

    function appendInlineMarkdown(parent, text) {
        const tokenPattern =
            /(\*\*[^*\n]+\*\*|`[^`\n]+`|\*[^*\n]+\*)/g;

        let lastIndex = 0;
        let match;

        while ((match = tokenPattern.exec(text)) !== null) {
            if (match.index > lastIndex) {
                parent.appendChild(
                    document.createTextNode(
                        text.slice(lastIndex, match.index)
                    )
                );
            }

            const token = match[0];

            if (
                token.startsWith("**")
                && token.endsWith("**")
            ) {
                const strong = document.createElement("strong");

                strong.textContent = token.slice(2, -2);

                parent.appendChild(strong);

            } else if (
                token.startsWith("`")
                && token.endsWith("`")
            ) {
                const code = document.createElement("code");

                code.textContent = token.slice(1, -1);

                parent.appendChild(code);

            } else if (
                token.startsWith("*")
                && token.endsWith("*")
            ) {
                const emphasis = document.createElement("em");

                emphasis.textContent = token.slice(1, -1);

                parent.appendChild(emphasis);
            }

            lastIndex = tokenPattern.lastIndex;
        }

        if (lastIndex < text.length) {
            parent.appendChild(
                document.createTextNode(
                    text.slice(lastIndex)
                )
            );
        }
    }


    function renderAssistantMarkdown(markdown, container) {
        const lines = String(markdown || "")
            .replace(/\r\n/g, "\n")
            .split("\n");

        let paragraphLines = [];
        let currentList = null;

        function flushParagraph() {
            if (paragraphLines.length === 0) {
                return;
            }

            const paragraph = document.createElement("p");

            appendInlineMarkdown(
                paragraph,
                paragraphLines.join(" ")
            );

            container.appendChild(paragraph);

            paragraphLines = [];
        }

        function closeList() {
            currentList = null;
        }

        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            const trimmed = line.trim();

            if (trimmed.startsWith("```")) {
                flushParagraph();
                closeList();

                const codeLines = [];

                index += 1;

                while (
                    index < lines.length
                    && !lines[index].trim().startsWith("```")
                ) {
                    codeLines.push(lines[index]);
                    index += 1;
                }

                const pre = document.createElement("pre");
                const code = document.createElement("code");

                code.textContent = codeLines.join("\n");

                pre.appendChild(code);
                container.appendChild(pre);

                continue;
            }

            if (!trimmed) {
                flushParagraph();
                closeList();
                continue;
            }

            const headingMatch = trimmed.match(
                /^(#{1,3})\s+(.+)$/
            );

            if (headingMatch) {
                flushParagraph();
                closeList();

                const level = headingMatch[1].length;
                const heading = document.createElement(
                    `h${level}`
                );

                appendInlineMarkdown(
                    heading,
                    headingMatch[2]
                );

                container.appendChild(heading);

                continue;
            }

            if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
                flushParagraph();
                closeList();

                container.appendChild(
                    document.createElement("hr")
                );

                continue;
            }

            const unorderedMatch = trimmed.match(
                /^[-+*]\s+(.+)$/
            );

            if (unorderedMatch) {
                flushParagraph();

                if (
                    !currentList
                    || currentList.tagName !== "UL"
                ) {
                    currentList = document.createElement("ul");
                    container.appendChild(currentList);
                }

                const item = document.createElement("li");

                appendInlineMarkdown(
                    item,
                    unorderedMatch[1]
                );

                currentList.appendChild(item);

                continue;
            }

            const orderedMatch = trimmed.match(
                /^\d+\.\s+(.+)$/
            );

            if (orderedMatch) {
                flushParagraph();

                if (
                    !currentList
                    || currentList.tagName !== "OL"
                ) {
                    currentList = document.createElement("ol");
                    container.appendChild(currentList);
                }

                const item = document.createElement("li");

                appendInlineMarkdown(
                    item,
                    orderedMatch[1]
                );

                currentList.appendChild(item);

                continue;
            }

            const quoteMatch = trimmed.match(
                /^>\s?(.+)$/
            );

            if (quoteMatch) {
                flushParagraph();
                closeList();

                const quote = document.createElement("blockquote");

                appendInlineMarkdown(
                    quote,
                    quoteMatch[1]
                );

                container.appendChild(quote);

                continue;
            }

            closeList();
            paragraphLines.push(trimmed);
        }

        flushParagraph();
    }

    function addChatMessage(message, sender) {
        if (!assistantChat) {
            return;
        }

        const messageElement =
            document.createElement("div");

        messageElement.classList.add(
            "chat-message"
        );

        if (sender === "user") {
            messageElement.classList.add(
                "user-message"
            );
        } else {
            messageElement.classList.add(
                "assistant-message"
            );
        }

        const avatar =
            document.createElement("div");

        avatar.classList.add(
            "message-avatar"
        );

        avatar.textContent =
            sender === "user"
                ? "You"
                : "AI";

        const content =
            document.createElement("div");

        content.classList.add(
            "message-content"
        );

        const senderLabel =
            document.createElement("span");

        senderLabel.textContent =
            sender === "user"
                ? "You"
                : "PhishGuard Assistant";

        const messageBody =
            document.createElement("div");

        messageBody.classList.add(
            "message-body"
        );

        if (sender === "user") {
            const paragraph =
                document.createElement("p");

            paragraph.textContent = message;

            messageBody.appendChild(
                paragraph
            );
        } else {
            renderAssistantMarkdown(
                message,
                messageBody
            );
        }

        content.appendChild(
            senderLabel
        );

        content.appendChild(
            messageBody
        );

        messageElement.appendChild(
            avatar
        );

        messageElement.appendChild(
            content
        );

        assistantChat.appendChild(
            messageElement
        );

        assistantChat.scrollTop =
            assistantChat.scrollHeight;
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

            const data = await response.json().catch(function () {
                return {};
            });

            if (!response.ok) {
                console.error(
                    "Assistant server error:",
                    data
                );

                let errorMessage =
                    data.reply
                    || "The assistant could not process your request.";

                if (response.status === 429) {
                    errorMessage =
                        "You're sending messages too quickly. Please wait a little and try again.";
                }

                addChatMessage(
                    errorMessage,
                    "assistant"
                );

                return;
            }

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

    // Browser-only Password Generator + Strength Checker
    const generatePasswordButton =
        document.getElementById("generatePasswordButton");

    const generatedPassword =
        document.getElementById("generatedPassword");

    const copyPasswordButton =
        document.getElementById("copyPasswordButton");

    const passwordLength =
        document.getElementById("passwordLength");

    const passwordLengthValue =
        document.getElementById("passwordLengthValue");

    const passwordStrengthInput =
        document.getElementById("passwordStrengthInput");

    const passwordStrengthLabel =
        document.getElementById("passwordStrengthLabel");

    const passwordStrengthScore =
        document.getElementById("passwordStrengthScore");

    const passwordStrengthFill =
        document.getElementById("passwordStrengthFill");

    const passwordStrengthFeedback =
        document.getElementById("passwordStrengthFeedback");


    if (passwordLength && passwordLengthValue) {
        passwordLength.addEventListener(
            "input",
            function () {
                passwordLengthValue.textContent =
                    passwordLength.value;
            }
        );
    }


    function secureRandomIndex(maximum) {
        if (
            !window.crypto
            || !window.crypto.getRandomValues
        ) {
            throw new Error(
                "Secure password generation is unavailable in this browser."
            );
        }

        const acceptedRange =
            Math.floor(256 / maximum) * maximum;

        const randomByte =
            new Uint8Array(1);

        do {
            window.crypto.getRandomValues(
                randomByte
            );
        } while (
            randomByte[0] >= acceptedRange
        );

        return randomByte[0] % maximum;
    }


    function secureChoice(characters) {
        return characters[
            secureRandomIndex(
                characters.length
            )
        ];
    }


    function secureShuffle(characters) {
        for (
            let index = characters.length - 1;
            index > 0;
            index -= 1
        ) {
            const randomIndex =
                secureRandomIndex(index + 1);

            const currentCharacter =
                characters[index];

            characters[index] =
                characters[randomIndex];

            characters[randomIndex] =
                currentCharacter;
        }

        return characters;
    }


    if (generatePasswordButton) {
        generatePasswordButton.addEventListener(
            "click",
            function () {
                const errorElement =
                    document.getElementById(
                        "generatorError"
                    );

                if (errorElement) {
                    errorElement.textContent = "";
                }

                try {
                    const ambiguousCharacters =
                        "Il1O0o";

                    const excludeAmbiguous =
                        document.getElementById(
                            "excludeAmbiguous"
                        )?.checked ?? false;

                    const selectedGroups = [];

                    if (
                        document.getElementById(
                            "useUppercase"
                        )?.checked
                    ) {
                        selectedGroups.push(
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        );
                    }

                    if (
                        document.getElementById(
                            "useLowercase"
                        )?.checked
                    ) {
                        selectedGroups.push(
                            "abcdefghijklmnopqrstuvwxyz"
                        );
                    }

                    if (
                        document.getElementById(
                            "useNumbers"
                        )?.checked
                    ) {
                        selectedGroups.push(
                            "0123456789"
                        );
                    }

                    if (
                        document.getElementById(
                            "useSymbols"
                        )?.checked
                    ) {
                        selectedGroups.push(
                            "!@#$%^&*()-_=+[]{}?"
                        );
                    }

                    if (
                        selectedGroups.length === 0
                    ) {
                        throw new Error(
                            "Select at least one character group."
                        );
                    }

                    const groups =
                        selectedGroups.map(
                            function (group) {
                                if (!excludeAmbiguous) {
                                    return group;
                                }

                                return Array.from(group)
                                    .filter(
                                        function (character) {
                                            return !ambiguousCharacters
                                                .includes(character);
                                        }
                                    )
                                    .join("");
                            }
                        );

                    const requestedLength =
                        Number.parseInt(
                            passwordLength
                                ? passwordLength.value
                                : "18",
                            10
                        );

                    const length = Math.max(
                        12,
                        Math.min(
                            requestedLength,
                            64
                        )
                    );

                    const combinedCharacters =
                        groups.join("");

                    const passwordCharacters =
                        groups.map(
                            secureChoice
                        );

                    while (
                        passwordCharacters.length
                        < length
                    ) {
                        passwordCharacters.push(
                            secureChoice(
                                combinedCharacters
                            )
                        );
                    }

                    if (generatedPassword) {
                        generatedPassword.value =
                            secureShuffle(
                                passwordCharacters
                            ).join("");
                    }

                } catch (error) {
                    if (errorElement) {
                        errorElement.textContent =
                            error.message;
                    }
                }
            }
        );
    }


    if (
        copyPasswordButton
        && generatedPassword
    ) {
        copyPasswordButton.addEventListener(
            "click",
            async function () {
                if (!generatedPassword.value) {
                    return;
                }

                try {
                    await navigator.clipboard.writeText(
                        generatedPassword.value
                    );

                    copyPasswordButton.textContent =
                        "Copied";

                    setTimeout(
                        function () {
                            copyPasswordButton.textContent =
                                "Copy";
                        },
                        1200
                    );

                } catch (error) {
                    copyPasswordButton.textContent =
                        "Copy failed";
                }
            }
        );
    }


    // Password Strength Checker

    function containsSimpleSequence(value) {
        const normalized =
            value.toLowerCase();

        const sequences = [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ];

        return sequences.some(
            function (sequence) {

                for (
                    let index = 0;
                    index <= sequence.length - 4;
                    index += 1
                ) {
                    const part =
                        sequence.slice(
                            index,
                            index + 4
                        );

                    const reversed =
                        Array.from(part)
                            .reverse()
                            .join("");

                    if (
                        normalized.includes(part)
                        || normalized.includes(
                            reversed
                        )
                    ) {
                        return true;
                    }
                }

                return false;
            }
        );
    }


    function setStrengthCheck(
        elementId,
        passed
    ) {
        const element =
            document.getElementById(
                elementId
            );

        if (!element) {
            return;
        }

        element.classList.toggle(
            "is-met",
            passed
        );

        element.classList.toggle(
            "is-unmet",
            !passed
        );

        const status =
            element.querySelector(
                ".check-status"
            );

        if (status) {
            status.textContent =
                passed
                    ? "✓"
                    : "○";
        }
    }


    function evaluatePasswordStrength(password) {
        const hasUpper =
            /[A-Z]/.test(password);

        const hasLower =
            /[a-z]/.test(password);

        const hasNumber =
            /\d/.test(password);

        const hasSymbol =
            /[^A-Za-z0-9]/.test(password);

        const normalized =
            password.toLowerCase();

        const commonFragments = [
            "password",
            "qwerty",
            "123456",
            "letmein",
            "welcome",
            "admin",
            "iloveyou"
        ];

        const hasCommonPattern =
            commonFragments.some(
                function (fragment) {
                    return normalized.includes(
                        fragment
                    );
                }
            );

        const hasSequence =
            containsSimpleSequence(
                password
            );

        const hasRepeatedCharacters =
            /(.)\1{2,}/.test(
                password
            );

        const varietyCount = [
            hasUpper,
            hasLower,
            hasNumber,
            hasSymbol
        ].filter(Boolean).length;


        let score = 0;

        if (password.length >= 8) {
            score = 1;
        }

        if (password.length >= 12) {
            score = 2;
        }

        if (password.length >= 16) {
            score = 3;
        }

        if (password.length >= 20) {
            score = 4;
        }

        if (
            password.length >= 12
            && varietyCount >= 3
        ) {
            score += 1;
        }

        if (
            password.length >= 16
            && varietyCount === 4
        ) {
            score += 1;
        }

        if (hasCommonPattern) {
            score -= 2;
        }

        if (hasSequence) {
            score -= 1;
        }

        if (hasRepeatedCharacters) {
            score -= 1;
        }

        score = Math.max(
            1,
            Math.min(score, 4)
        );


        return {
            score: score,

            hasUpper: hasUpper,
            hasLower: hasLower,
            hasNumber: hasNumber,
            hasSymbol: hasSymbol,

            safePattern:
                !hasCommonPattern
                && !hasSequence
                && !hasRepeatedCharacters
        };
    }


    function updatePasswordStrength() {
        if (
            !passwordStrengthInput
            || !passwordStrengthLabel
            || !passwordStrengthFill
        ) {
            return;
        }

        const password =
            passwordStrengthInput.value;


        if (!password) {
            passwordStrengthLabel.textContent =
                "Not checked";

            if (passwordStrengthScore) {
                passwordStrengthScore.textContent =
                    "0/4";
            }

            passwordStrengthFill.style.width =
                "0%";

            passwordStrengthFill.className =
                "strength-meter-fill";

            if (passwordStrengthFeedback) {
                passwordStrengthFeedback.textContent =
                    "Enter a new or sample password to evaluate it.";
            }

            [
                "checkLength",
                "checkCases",
                "checkNumber",
                "checkSymbol",
                "checkPattern"
            ].forEach(
                function (id) {
                    setStrengthCheck(
                        id,
                        false
                    );
                }
            );

            return;
        }


        const result =
            evaluatePasswordStrength(
                password
            );

        const labels = {
            1: "Weak",
            2: "Fair",
            3: "Good",
            4: "Strong"
        };

        const feedback = {
            1:
                "This password is easy to guess. Increase its length and avoid predictable patterns.",

            2:
                "This is better, but additional length or variety would improve it.",

            3:
                "This password has good strength. A longer unique password would improve it further.",

            4:
                "Strong password characteristics detected. Keep it unique and store it securely."
        };


        passwordStrengthLabel.textContent =
            labels[result.score];

        if (passwordStrengthScore) {
            passwordStrengthScore.textContent =
                result.score + "/4";
        }

        passwordStrengthFill.style.width =
            (result.score * 25) + "%";

        passwordStrengthFill.className =
            "strength-meter-fill level-"
            + result.score;


        if (passwordStrengthFeedback) {
            passwordStrengthFeedback.textContent =
                feedback[result.score];
        }


        setStrengthCheck(
            "checkLength",
            password.length >= 12
        );

        setStrengthCheck(
            "checkCases",
            result.hasUpper
            && result.hasLower
        );

        setStrengthCheck(
            "checkNumber",
            result.hasNumber
        );

        setStrengthCheck(
            "checkSymbol",
            result.hasSymbol
        );

        setStrengthCheck(
            "checkPattern",
            result.safePattern
        );
    }


    if (passwordStrengthInput) {
        passwordStrengthInput.addEventListener(
            "input",
            updatePasswordStrength
        );
    }

});