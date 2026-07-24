const slides = Array.from(document.querySelectorAll(".slide"));
const prevButton = document.getElementById("prevSlide");
const nextButton = document.getElementById("nextSlide");
const indicator = document.getElementById("slideIndicator");
const slider = document.getElementById("offsetSlider");
const offsetValue = document.getElementById("offsetValue");
const accessMarker = document.getElementById("accessMarker");
const x86Result = document.getElementById("x86Result");
const cheriResult = document.getElementById("cheriResult");

let currentSlide = 0;

function showSlide(index) {
  currentSlide = Math.max(0, Math.min(slides.length - 1, index));
  slides.forEach((slide, slideIndex) => {
    slide.classList.toggle("active", slideIndex === currentSlide);
  });
  indicator.textContent = `${currentSlide + 1} / ${slides.length}`;
  prevButton.disabled = currentSlide === 0;
  nextButton.disabled = currentSlide === slides.length - 1;
}

function updateBounds(offset) {
  const boundedLength = 16;
  const maxOffset = Number(slider.max);
  const boundedVisualWidth = 40;
  const visualPercent = offset <= boundedLength
    ? (offset / boundedLength) * boundedVisualWidth
    : boundedVisualWidth + ((offset - boundedLength) / (maxOffset - boundedLength)) * (100 - boundedVisualWidth);
  const isAllowed = offset + 8 <= boundedLength;

  offsetValue.textContent = `${offset} bytes`;
  accessMarker.style.left = `${Math.min(100, Math.max(0, visualPercent))}%`;

  x86Result.textContent = offset + 8 <= boundedLength
    ? "in-bounds load"
    : "raw address computed";
  x86Result.className = offset + 8 <= boundedLength ? "result ok" : "result warn";

  cheriResult.textContent = isAllowed ? "allowed" : "bounds trap";
  cheriResult.className = isAllowed ? "result ok" : "result trap";
}

prevButton.addEventListener("click", () => showSlide(currentSlide - 1));
nextButton.addEventListener("click", () => showSlide(currentSlide + 1));

document.addEventListener("keydown", (event) => {
  if (event.key === "ArrowRight" || event.key === "PageDown" || event.key === " ") {
    event.preventDefault();
    showSlide(currentSlide + 1);
  }
  if (event.key === "ArrowLeft" || event.key === "PageUp") {
    event.preventDefault();
    showSlide(currentSlide - 1);
  }
  if (event.key === "Home") {
    event.preventDefault();
    showSlide(0);
  }
  if (event.key === "End") {
    event.preventDefault();
    showSlide(slides.length - 1);
  }
});

slider.addEventListener("input", () => updateBounds(Number(slider.value)));

document.querySelectorAll("[data-offset]").forEach((button) => {
  button.addEventListener("click", () => {
    slider.value = button.dataset.offset;
    updateBounds(Number(slider.value));
  });
});

showSlide(0);
updateBounds(Number(slider.value));
