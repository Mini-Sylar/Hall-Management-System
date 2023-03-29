const body = document.querySelector("body");
{
  if (screen.width < 750) {
    body.style = `
display:flex;
align-items:center;
text-align:center;
`;

    body.innerHTML = `
    <!-- Main Body -->
<div class="mainpage">
        <div class="main-01">
          <div class="default-text">
           FOR THE BEST EXPERIENCE USE A TABLET, LAPTOP OR A DESKTOP 😊 <br/>
           MOBILE VERSION IS CURRENTLY A WIP 🚧
          </div>
        </div>
</div>      
    `;

    console.log("Mobile Detected");
  }
}
