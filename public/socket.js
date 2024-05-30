// main.js (cliente)
// Conexión al Servidor WebSocket
var socket = io.connect("https://manejador.azurewebsites.net"); // Nos conectamos al socket del servidor

const userMessage = (message) => { // Esta funcion es para genera el html dinamico donde construimos el mensaje del usuario
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

const serverMessage = (autor, message) => { // Funcion del mensaje dinamico que construie el mensaje de usuarios que nos soy yo
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
socket.emit("connection", function (mensaje) { // Validar que podemos conectarnos al socket
  console.log("Respuesta del servidor:");
});

// Manejar el evento 'respuesta' del servidor
socket.on("message", function (messages) {
  const userName = localStorage.getItem("username"); // Validar si loe mensajes son del usario o de otro usuario
  const messageList = document.getElementById("message-list"); // Recuperamos el id del chat para insertar los mensajes

  messages.map((message) => { // Hacemos el mapeo del servidor y tiene 2 propietades que el autor y el texto
    const { autor, texto } = message;
    if (autor === userName) { // es para concatenar al contenedor de mensajes que todos los mensajes que sean mios
      messageList.innerHTML += userMessage(texto);
    } else {  // Si el usario no soy yo concatename todos los mensajes que no son mios
      messageList.innerHTML += serverMessage(autor, texto);
    }
  });
  setTimeout(scrollMethod, 100); // Timer para que escrolea al final del chat
});

document.getElementById("send-message").addEventListener("click", function () { // Recupermos el botton y pnemos un escuhador click
  const input = document.getElementById("message-input"); // Recuperamos el input
  const message = input.value; // Recuperamos el mensaje que es el valor del input
  if (!message) { // Si el mensaje esta vacio que le mande una lerta que no tiene nada
    alert("Por favor, escribe un mensaje");
  }
  const userName = localStorage.getItem("username"); // Recuperamos el usario de local storache
  const payload = { // Hace el payload que se le envia al backend y tiene 2 propiedades de autor y texto
    autor: userName,
    texto: message,
  };
  socket.emit("new-message", payload); // Emite un mensaje para que insete en la base de datos 
  location.reload(); // Recarga la pagina y escuha los mensajes y lo vuelve a recargar
});

const scrollMethod = () => { // Recupera el contenedor de los mensajes
  const messageList = document.getElementById("message-list");

  messageList.scrollTo({ // Indica el scroll al contenedor de manera suave
    top: messageList.scrollHeight,
    behavior: "smooth",
  });
};
