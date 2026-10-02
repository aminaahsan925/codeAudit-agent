import { exec } from "child_process";

// js_dangerous_eval in typed TypeScript
function renderWidget(userInput: string): unknown {
  const output: unknown = eval(userInput);
  return output;
}

// js_react_dangerous_html in TSX
const ProfileCard = ({ userHtml }: { userHtml: string }) => (
  <div className="profile" dangerouslySetInnerHTML={{ __html: userHtml }} />
);

// js_sql_string_construction: template literal with substitution
async function getUser(db: Database, id: number): Promise<Row[]> {
  const rows: Row[] = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  return rows;
}

export { renderWidget, ProfileCard, getUser };
