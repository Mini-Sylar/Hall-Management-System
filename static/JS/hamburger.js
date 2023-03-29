const hamburger = document.querySelector(".hamburger");
const mobile_menu = document.querySelector(".mobile-navbar");
const body = document.querySelector("body");
hamburger.addEventListener("click", () => {
  mobile_menu.classList.toggle("showlinks");
  if (mobile_menu.classList.contains("showlinks")) {
    body.style = `
    margin: 0;
    height: 100vh;
    overflow: hidden;
    `;
  } else {
    body.style = `
    
    `;
  }
});
