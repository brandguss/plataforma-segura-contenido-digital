/* Marca que JavaScript está disponible antes de pintar la página.
   Así las animaciones de aparición solo ocultan contenido si el script
   que lo vuelve a mostrar (app.js) va a ejecutarse. */
document.documentElement.classList.add("js");
