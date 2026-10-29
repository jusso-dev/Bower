/* Give Material's dynamically created code controls distinct landmark names.
 * Keep the existing copy controls and keyboard behavior. */
(() => {
  const article = document.querySelector('article');
  if (!article) return;
  const label = () => article.querySelectorAll('.md-code__nav').forEach((nav, index) => {
    nav.setAttribute('aria-label', `Code block ${index + 1} actions`);
  });
  label();
  const observer = new MutationObserver(label);
  observer.observe(article, { childList: true, subtree: true });
  window.addEventListener('pagehide', () => observer.disconnect(), { once: true });
})();

/* Local illustration only. No telemetry, network calls or customer event data. */
(() => {
  const root = document.querySelector('.bower-home');
  if (!root) return;
  root.classList.add('motion-ready');
  const svg = root.querySelector('.flow-map');
  const toggle = root.querySelector('[data-motion-toggle]');
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let paused = motion.matches;
  const applyMotion = () => {
    const stopped = paused || motion.matches;
    root.dataset.motionPaused = String(stopped);
    if (stopped) svg.pauseAnimations(); else svg.unpauseAnimations();
    toggle.textContent = stopped ? 'Play animation' : 'Pause animation';
    toggle.setAttribute('aria-pressed', String(stopped));
    toggle.hidden = motion.matches;
  };
  toggle.addEventListener('click', () => { paused = !paused; applyMotion(); });
  motion.addEventListener('change', applyMotion);
  applyMotion();

  const stages = {
    collect: ['Start with a security event', 'A sign-in failed. That matters.', 'A collector receives a security event from an application, machine or cloud source. Bower is for meaningful security telemetry, not every log line.', 'Received by collector', 'Redaction before storage', 'Not yet verified'],
    select: ['Keep the signal', 'Keep what your policy allows.', 'Deterministic rules select approved event types. Unknown events are denied by default. Every selection follows explicit policy, not a runtime AI decision.', 'Allowed by event policy', 'Redaction before storage', 'Not yet verified'],
    arrange: ['Protect before persistence', 'Useful fields. Sensitive details removed.', 'A trusted parser structures the event. Privacy rules remove or mask sensitive details before the event enters the durable queue.', 'Structured and queued', 'Protected before persistence', 'Not yet verified'],
    deliver: ['Send with acknowledgement', 'A queue that waits for acceptance.', 'The collector sends approved, protected events through the configured output. Retries and acknowledgement preserve delivery state. An accepted request is still not proof of arrival.', 'Sent through configured output', 'Protected event only', 'Acceptance is not proof'],
    prove: ['Check the destination', 'Find the event. Keep the evidence.', 'For a canary, Bower queries Sentinel for the exact test event and records the result in an evidence bundle. The bundle is signed only when a signing key is configured; otherwise it is unsigned. A simulated run skips the query and is not proof.', 'Destination query', 'Protected event only', 'Verified only when found']
  };
  root.querySelectorAll('[data-step]').forEach(button => {
    button.addEventListener('click', () => {
      const stage = stages[button.dataset.step];
      root.querySelectorAll('[data-step]').forEach(other => {
        other.classList.toggle('is-active', other === button);
        other.setAttribute('aria-pressed', String(other === button));
      });
      ['label', 'title', 'copy'].forEach((field, index) => root.querySelector(`[data-detail-${field}]`).textContent = stage[index]);
      ['stage', 'protection', 'evidence'].forEach((field, index) => root.querySelector(`[data-${field}]`).textContent = stage[index + 3]);
    });
  });
})();
