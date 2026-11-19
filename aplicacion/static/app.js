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
    if (e.defaultPrevented || formulario.method.toLowerCase() !== "post") return;
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

  /* 5. Verificador de requisitos de contraseña (registro, perfil, restablecer).
        El servidor aplica exactamente las mismas reglas en seguridad.validar_password. */
  var REGLAS = {
    longitud: function (v, min) { return v.length >= min; },
    mayuscula: function (v) { return /[A-ZÁÉÍÓÚÑ]/.test(v); },
    minuscula: function (v) { return /[a-záéíóúñ]/.test(v); },
    numero: function (v) { return /\d/.test(v); }
  };
  var NIVELES = ["Muy débil", "Débil", "Aceptable", "Buena", "Fuerte"];

  document.querySelectorAll(".requisitos").forEach(function (lista) {
    var formulario = lista.closest("form");
    var campo = formulario.querySelector('[name="' + lista.dataset.campo + '"]');
    var confirmar = formulario.querySelector('[name="' + lista.dataset.confirmar + '"]');
    var minimo = parseInt(lista.dataset.min, 10) || 10;
    var barra = formulario.querySelector(".fuerza-barra");
    var texto = formulario.querySelector(".fuerza-texto");
    lista.classList.add("activa");

    function evaluar() {
      var v = campo.value, cumplidas = 0, total = 0;
      lista.querySelectorAll("li").forEach(function (li) {
        var regla = li.dataset.regla, ok;
        if (regla === "coincide") ok = v.length > 0 && confirmar && v === confirmar.value;
        else { ok = REGLAS[regla](v, minimo); total++; if (ok) cumplidas++; }
        li.classList.toggle("cumple", !!ok);
      });
      // Nivel: reglas cumplidas, más un extra por símbolo y otro por longitud amplia
      var nivel = cumplidas === total ? 2 : Math.min(cumplidas, 1);
      if (cumplidas === total && /[^A-Za-z0-9ÁÉÍÓÚÑáéíóúñ]/.test(v)) nivel++;
      if (cumplidas === total && v.length >= minimo + 4) nivel++;
      if (barra) {
        barra.style.width = v ? (nivel + 1) * 20 + "%" : "0";
        barra.dataset.nivel = v ? nivel : "";
      }
      if (texto) texto.textContent = v ? "Seguridad: " + NIVELES[nivel] : "";
      return cumplidas === total && (!confirmar || v === confirmar.value);
    }

    campo.addEventListener("input", evaluar);
    if (confirmar) confirmar.addEventListener("input", evaluar);
    // Fase de captura: corre antes del estado "procesando" de los botones
    formulario.addEventListener("submit", function (e) {
      if (evaluar()) return;
      e.preventDefault();
      lista.classList.remove("sacudir"); void lista.offsetWidth; lista.classList.add("sacudir");
      campo.focus();
    }, true);
  });

  /* 6. Botón para mostrar u ocultar la contraseña (inputs con data-ojo) */
  var OJO = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
    '<path class="ojo-abierto" d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/>' +
    '<circle class="ojo-abierto" cx="12" cy="12" r="3"/>' +
    '<path class="ojo-cerrado" d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>' +
    '</svg>';
  document.querySelectorAll("input[type=password][data-ojo]").forEach(function (input) {
    var envoltura = document.createElement("span");
    envoltura.className = "campo-clave";
    input.parentNode.insertBefore(envoltura, input);
    envoltura.appendChild(input);
    var boton = document.createElement("button");
    boton.type = "button";
    boton.className = "ojo";
    boton.setAttribute("aria-label", "Mostrar contraseña");
    boton.setAttribute("aria-pressed", "false");
    boton.innerHTML = OJO;
    envoltura.appendChild(boton);
    boton.addEventListener("click", function () {
      var visible = input.type === "password";
      input.type = visible ? "text" : "password";
      boton.classList.toggle("visible", visible);
      boton.setAttribute("aria-pressed", String(visible));
      boton.setAttribute("aria-label", visible ? "Ocultar contraseña" : "Mostrar contraseña");
      input.focus();
    });
  });
  /* Antes de enviar, los campos vuelven a ser de tipo password (el navegador no los guarda como texto) */
  document.addEventListener("submit", function (e) {
    e.target.querySelectorAll(".campo-clave input").forEach(function (i) { i.type = "password"; });
  }, true);
})();
