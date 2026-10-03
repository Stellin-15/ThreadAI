// The safe version of vulnerable/Comment.jsx. ThreadAI must report nothing here.
import DOMPurify from "dompurify";

export function Comment({ comment }) {
  return <div>{comment.body}</div>;
}

export function RichComment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function showHash() {
  const out = document.getElementById("out");
  out.innerHTML = "";
  out.textContent = location.hash.slice(1);
}
