// main.js (cliente)
// Conexión al Servidor WebSocket
var socket = io.connect("https://manejador.azurewebsites.net");

const userMessage = (message) => {
  return `<div class="flex w-full mt-2 space-x-3 max-w-xs ml-auto justify-end">
                <div>
                    <div class="bg-blue-600 text-white p-3 rounded-l-lg rounded-br-lg">
                        <p class="text-sm">${message}</p>
                    </div>
                    <span class="text-xs text-gray-500 leading-none">Enviado por ti</span>
                </div>
                <div class="flex-shrink-0 h-10 w-10 rounded-full bg-gray-300"></div>
            </div>`;
};

const serverMessage = (autor, message) => {
  return `<div class="flex w-full mt-2 space-x-3 max-w-xs">
                <div class="flex-shrink-0 h-10 w-10 rounded-full bg-gray-300"></div>
                <div>
                    <div class="bg-gray-300 p-3 rounded-r-lg rounded-bl-lg">
                        <p class="text-sm">${message}</p>
                    </div>
                    <span class="text-xs text-gray-500 leading-none">Enviado por ${autor}</span>
                </div>
            </div>`;
};

// Escuchar un evento del servidor
socket.emit("connection", function (mensaje) {
  console.log("Respuesta del servidor:");
});

// Manejar el evento 'respuesta' del servidor
socket.on("message", function (messages) {
  const userName = localStorage.getItem("username");
  const messageList = document.getElementById("message-list");

  messages.map((message) => {
    const { autor, texto } = message;
    if (autor === userName) {
      messageList.innerHTML += userMessage(texto);
    } else {
      messageList.innerHTML += serverMessage(autor, texto);
    }
  });
  setTimeout(scrollMethod, 100);
});

document.getElementById("send-message").addEventListener("click", function () {
  const input = document.getElementById("message-input");
  const message = input.value;
  if (!message) {
    alert("Por favor, escribe un mensaje");
  }
  const userName = localStorage.getItem("username");
  const payload = {
    autor: userName,
    texto: message,
  };
  socket.emit("new-message", payload);
  location.reload();
});

const scrollMethod = () => {
  const messageList = document.getElementById("message-list");

  messageList.scrollTo({
    top: messageList.scrollHeight,
    behavior: "smooth",
  });
};
