document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.querySelector(".main-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("nav-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.querySelectorAll("a").forEach(a => a.addEventListener("click", () => {
      nav.classList.remove("nav-open");
      toggle.setAttribute("aria-expanded", "false");
    }));
  }
  const year = document.getElementById("year");
  if (year) year.textContent = new Date().getFullYear();
  document.querySelectorAll("form[data-confirm]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!window.confirm(form.dataset.confirm || "Are you sure?")) event.preventDefault();
    });
  });
  document.querySelectorAll(".flash").forEach(el => {
    window.setTimeout(() => el.classList.add("flash-fade"), 6000);
  });
});
