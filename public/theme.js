// Tema: auto (ikut sistem) -> terang -> gelap. Disimpan di localStorage.
(function () {
  var KEY = "theme", root = document.documentElement;
  var modes = ["auto", "light", "dark"];
  var names = { auto: "Otomatis", light: "Terang", dark: "Gelap" };

  function get() {
    try { var v = localStorage.getItem(KEY); return modes.indexOf(v) > -1 ? v : "auto"; }
    catch (e) { return "auto"; }
  }
  function apply(m) {
    if (m === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", m);
  }

  apply(get()); // dijalankan di <head> agar tidak berkedip

  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("theme");
    if (!b) return;
    function label() {
      var n = names[get()];
      b.textContent = "Tema: " + n;
      b.setAttribute("aria-label", "Ganti tema, sekarang " + n.toLowerCase());
    }
    b.addEventListener("click", function () {
      var m = modes[(modes.indexOf(get()) + 1) % modes.length];
      try { localStorage.setItem(KEY, m); } catch (e) {}
      apply(m); label();
    });
    window.addEventListener("storage", function () { apply(get()); label(); });
    label();
  });
})();
