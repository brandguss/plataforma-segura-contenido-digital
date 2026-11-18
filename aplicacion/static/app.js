/* =====================================================================
   Animaciones de la interfaz. Archivo externo para cumplir la CSP
   (script-src 'self': no se permiten scripts en línea).
   Nada de lo que hay aquí es necesario para que la app funcione:
   si el script no carga, todo sigue operando sin animaciones.
   ===================================================================== */
(function () {
  "use strict";

  var sinMovimiento = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* 1. Onda en los botones al hacer clic */
  document.addEventListener("pointerdown", function (e) {
    var boton = e.target.closest(".boton");
    if (!boton || sinMovimiento) return;
    var caja = boton.getBoundingClientRect();
    var tam = Math.max(caja.width, caja.height);
    var onda = document.createElement("span");
    onda.className = "onda";
    onda.style.width = onda.style.height = tam + "px";
    onda.style.left = (e.clientX - caja.left - tam / 2) + "px";
    onda.style.top = (e.clientY - caja.top - tam / 2) + "px";
    boton.appendChild(onda);
    onda.addEventListener("animationend", function () { onda.remove(); });
  });

  /* 2. Estado "procesando" al enviar un formulario (también evita doble envío) */
  document.addEventListener("submit", function (e) {
    var formulario = e.target;
    if (formulario.method.toLowerCase() !== "post") return;
    var boton = e.submitter && e.submitter.classList.contains("boton")
      ? e.submitter
      : formulario.querySelector("button.boton");
    if (!boton) return;
    if (boton.classList.contains("cargando")) { e.preventDefault(); return; }
    boton.classList.add("cargando");
    boton.setAttribute("aria-busy", "true");
  });

  /* Al volver con el botón "atrás", el navegador puede restaurar la página
     desde caché: se quita el estado de carga. */
  window.addEventListener("pageshow", function () {
    document.querySelectorAll(".boton.cargando").forEach(function (b) {
      b.classList.remove("cargando");
      b.removeAttribute("aria-busy");
    });
  });

  /* 3. Aparición escalonada de documentos y paneles al hacer scroll */
  var revelables = document.querySelectorAll(".revelar");
  if (!("IntersectionObserver" in window) || sinMovimiento) {
    revelables.forEach(function (el) { el.classList.add("visible"); });
  } else {
    var observador = new IntersectionObserver(function (entradas) {
      entradas.forEach(function (entrada) {
        if (!entrada.isIntersecting) return;
        var el = entrada.target;
        var hermanos = Array.prototype.indexOf.call(el.parentNode.children, el);
        el.style.transitionDelay = Math.min(hermanos, 6) * 90 + "ms";
        el.classList.add("visible");
        el.addEventListener("transitionend", function limpiar() {
          el.style.transitionDelay = "";
          el.removeEventListener("transitionend", limpiar);
        });
        observador.unobserve(el);
      });
    }, { threshold: 0.05, rootMargin: "0px 0px -40px 0px" });
    revelables.forEach(function (el) { observador.observe(el); });
  }

  /* 4. Contadores de los indicadores del administrador */
  document.querySelectorAll(".indicador b").forEach(function (el) {
    var final = parseInt(el.textContent, 10);
    if (isNaN(final) || final === 0 || sinMovimiento) return;
    var inicio = null, duracion = 900;
    function paso(t) {
      if (inicio === null) inicio = t;
      var avance = Math.min((t - inicio) / duracion, 1);
      var suavizado = 1 - Math.pow(1 - avance, 3);
      el.textContent = Math.round(final * suavizado);
      if (avance < 1) requestAnimationFrame(paso);
    }
    el.textContent = "0";
    requestAnimationFrame(paso);
  });
})();
