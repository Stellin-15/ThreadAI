// Intentionally vulnerable sample for ThreadAI tests. NEVER deploy this.
export function Comment({ comment }) {
  // expect: TAI-JS-002
  return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;
}

export function showHash() {
  // expect: TAI-JS-001
  document.getElementById("out").innerHTML = location.hash.slice(1);
}
