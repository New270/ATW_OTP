// Các phần tử Trang Đăng ký & Phương thức
const signup = document.getElementById("signup");
const method = document.getElementById("method");
const verify = document.getElementById("verify");
const done = document.getElementById("done");

// Các phần tử Trang Đăng nhập (MỚI)
const loginPage = document.getElementById("login");
const loginForm = document.getElementById("loginForm");
const loginContact = document.getElementById("loginContact");
const loginPassword = document.getElementById("loginPassword");
const loginError = document.getElementById("loginError");
const loginButton = document.getElementById("loginButton");

const goToSignup = document.getElementById("goToSignup");
const goToLogin = document.getElementById("goToLogin");

// Form & Buttons
const signupForm = document.getElementById("signupForm");
const nameInput = document.getElementById("name");
const contactInput = document.getElementById("contact");
const passwordInput = document.getElementById("password");
const termsInput = document.getElementById("terms");
const signupError = document.getElementById("signupError");
const methods = document.querySelectorAll(".method");

const startButton = document.getElementById("start");
const confirmButton = document.getElementById("confirm");
const againButton = document.getElementById("again");

const verifyTitle = document.getElementById("verifyTitle");
const verifySub = document.getElementById("verifySub");
const qrArea = document.getElementById("qrArea");
const qr = document.getElementById("qr");
const otp = document.getElementById("otp");
const otpInputs = otp.querySelectorAll("input");
const resend = document.getElementById("resend");
const resendButton = resend.querySelector("button");
const toast = document.getElementById("toast");

/* ================= TRẠNG THÁI ================= */
let selectedMethod = "email";
let loading = false;

/* ================= CHUYỂN BƯỚC ================= */
function showPage(page) {
    document.querySelectorAll(".page").forEach(item => {
        item.classList.remove("visible");
    });
    page.classList.add("visible");
}

/* ================= NÚT CHUYỂN ĐỔI ĐĂNG NHẬP / ĐĂNG KÝ ================= */
goToSignup.addEventListener("click", () => showPage(signup));
goToLogin.addEventListener("click", () => showPage(loginPage));

/* ================= TOAST & BUTTON LOADING ================= */
function showToast(message, isError = false) {
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.classList.add("show");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => { toast.classList.remove("show"); }, 3500);
}

function setButtonLoading(button, isLoading, text) {
    button.disabled = isLoading;
    if (isLoading) {
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = text;
    } else {
        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
            delete button.dataset.originalText;
        }
    }
}

/* ================= GỌI BACKEND ================= */
async function requestAPI(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        ...options
    });
    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error("Backend trả về dữ liệu không hợp lệ.");
    }
    if (!response.ok || data.ok === false) {
        throw new Error(data.message || "Có lỗi xảy ra.");
    }
    return data;
}

/* ================= BƯỚC ĐĂNG NHẬP (LUỒNG MỚI) ================= */
loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    loginError.textContent = "";

    if (!loginForm.checkValidity()) {
        loginForm.reportValidity();
        return;
    }

    loading = true;
    setButtonLoading(loginButton, true, "Đang kiểm tra...");

    try {
        const data = await requestAPI("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
                contact: loginContact.value.trim(),
                password: loginPassword.value
            })
        });

        // Backend trả về phương thức xác thực mà tài khoản đã đăng ký (ví dụ: 'app')
        selectedMethod = data.method;
        
        // Gọi hàm cấu hình giao diện Verify (Truyền data rỗng QR vì đăng nhập không cần QR)
        configureVerifyPage(data);
        clearOTP();
        showPage(verify);
        showToast(data.message);

    } catch (error) {
        loginError.textContent = error.message;
    } finally {
        loading = false;
        setButtonLoading(loginButton, false);
    }
});

/* ================= BƯỚC ĐĂNG KÝ ================= */
signupForm.addEventListener("submit", function (event) {
    event.preventDefault();
    signupError.textContent = "";

    if (!signupForm.checkValidity()) {
        signupForm.reportValidity();
        return;
    }
    const password = passwordInput.value;
    if (password.length < 8) {
        signupError.textContent = "Mật khẩu phải có ít nhất 8 ký tự.";
        return;
    }
    if (!termsInput.checked) {
        signupError.textContent = "Bạn cần đồng ý với Điều khoản.";
        return;
    }
    showPage(method);
});

/* ================= CHỌN PHƯƠNG THỨC 2FA ================= */
methods.forEach(button => {
    button.addEventListener("click", function () {
        methods.forEach(item => item.classList.remove("selected"));
        this.classList.add("selected");
        selectedMethod = this.dataset.method;
    });
});

/* ================= TẠO TÀI KHOẢN & LẤY QR ================= */
startButton.addEventListener("click", async function () {
    if (loading) return;
    loading = true;
    setButtonLoading(startButton, true, "Đang xử lý...");

    try {
        const data = await requestAPI("/api/auth/start", {
            method: "POST",
            body: JSON.stringify({
                name: nameInput.value.trim(),
                contact: contactInput.value.trim(),
                password: passwordInput.value,
                method: selectedMethod
            })
        });

        configureVerifyPage(data);
        clearOTP();
        showPage(verify);
        showToast("Tạo tài khoản thành công. Vui lòng thiết lập bảo mật.");

    } catch (error) {
        showToast(error.message, true);
        showPage(signup);
    } finally {
        loading = false;
        setButtonLoading(startButton, false);
    }
});

/* ================= HIỂN THỊ BƯỚC XÁC THỰC ================= */
function configureVerifyPage(data) {
    qrArea.style.display = "none";
    resend.style.display = "none";
    otp.style.display = "flex";

    if (selectedMethod === "email") {
        verifyTitle.textContent = "Nhập mã Email";
        verifySub.textContent = "Mã xác thực đã được gửi đến email của bạn.";
        resend.style.display = "block";
    }
    if (selectedMethod === "sms") {
        verifyTitle.textContent = "Nhập mã SMS";
        verifySub.textContent = "Mã xác thực đã được gửi đến số điện thoại.";
        resend.style.display = "block";
    }
    if (selectedMethod === "app") {
        verifyTitle.textContent = "Bảo mật 2 lớp (2FA)";
        verifySub.textContent = "Mở ứng dụng Google Authenticator và nhập mã 6 số.";
        
        // NẾU LÀ ĐĂNG KÝ (Có mã QR trả về)
        if (data.qr) {
            qr.onload = function () { qrArea.style.display = "block"; };
            qr.onerror = function () { showToast("Lỗi tải mã QR.", true); };
            qr.src = data.qr;
            verifyTitle.textContent = "Thiết lập Google Authenticator";
        }
        // NẾU LÀ ĐĂNG NHẬP (Không có mã QR) -> Ẩn mã QR (qrArea mặc định đã display: none ở trên)
        resend.style.display = "none";
    }
}

/* ================= XỬ LÝ Ô NHẬP OTP ================= */
otpInputs.forEach((input, index) => {
    input.addEventListener("input", function () {
        this.value = this.value.replace(/\D/g, "").slice(0, 1);
        if (this.value && index < otpInputs.length - 1) {
            otpInputs[index + 1].focus();
        }
    });
    input.addEventListener("keydown", function (event) {
        if (event.key === "Backspace" && this.value === "" && index > 0) {
            otpInputs[index - 1].focus();
        }
    });
    input.addEventListener("paste", function (event) {
        event.preventDefault();
        const value = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
        value.split("").forEach((number, i) => {
            if (otpInputs[i]) otpInputs[i].value = number;
        });
        if (value.length === 6) otpInputs[5].focus();
    });
});

function getOTP() {
    return Array.from(otpInputs).map(input => input.value).join("");
}

function clearOTP() {
    otpInputs.forEach(input => input.value = "");
}

/* ================= XÁC NHẬN OTP LÊN SERVER ================= */
confirmButton.addEventListener("click", async function () {
    if (loading) return;
    const code = getOTP();

    if (!/^\d{6}$/.test(code)) {
        showToast("Vui lòng nhập đủ 6 chữ số.", true);
        return;
    }
    loading = true;
    setButtonLoading(confirmButton, true, "Đang kiểm tra...");

    try {
        const data = await requestAPI("/api/auth/verify", {
            method: "POST",
            body: JSON.stringify({ otp: code })
        });
        showPage(done);
        showToast(data.message);
    } catch (error) {
        showToast(error.message, true);
    } finally {
        loading = false;
        setButtonLoading(confirmButton, false);
    }
});

/* ================= GỬI LẠI OTP ================= */
resendButton.addEventListener("click", async function () {
    if (loading) return;
    loading = true;
    resendButton.disabled = true;

    try {
        const data = await requestAPI("/api/auth/resend", { method: "POST", body: JSON.stringify({}) });
        clearOTP();
        showToast(data.message);
    } catch (error) {
        showToast(error.message, true);
    } finally {
        loading = false;
        resendButton.disabled = false;
    }
});

/* ================= NÚT QUAY LẠI ================= */
document.querySelectorAll(".back").forEach(button => {
    button.addEventListener("click", function () {
        const target = this.dataset.to;
        if (target === "signup") showPage(signup);
    });
});

/* ================= VỀ TRANG CHỦ ================= */
againButton.addEventListener("click", function () {
    loginForm.reset();
    signupForm.reset();
    clearOTP();
    selectedMethod = "email";
    methods.forEach((button, index) => button.classList.toggle("selected", index === 0));
    
    qrArea.style.display = "none";
    resend.style.display = "none";
    signupError.textContent = "";
    loginError.textContent = "";

    // Mặc định về trang đăng nhập
    showPage(loginPage);
});