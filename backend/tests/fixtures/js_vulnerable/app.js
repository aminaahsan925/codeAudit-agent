const crypto = require("crypto");
const childProcess = require("child_process");

// js_dangerous_eval: arbitrary string executed as code
const result = eval(userInput);

// js_function_constructor: eval by another name
const adder = new Function("a", "b", "return a + b");

// js_command_injection: shell:true with a built command ...
childProcess.exec("ls " + userDir, { shell: true }, (err, out) => console.log(out));
// ... and execSync with a non-literal command
const listing = childProcess.execSync("cat " + fileName);

// js_xss_dom_sink: non-literal HTML assignment ...
profileElement.innerHTML = userComment;
// ... and document.write
document.write("<p>Welcome, " + userName + "</p>");

// js_react_dangerous_html via createElement props
const widget = React.createElement("div", {
  dangerouslySetInnerHTML: { __html: rawHtml },
});

// js_hardcoded_secret: secret-like name, literal value
const apiKey = "sk-live-9f8e7d6c5b4a3928173645";

// js_sql_string_construction: template literal with substitution ...
const users = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
// ... and string concatenation
const orders = await db.execute("SELECT * FROM orders WHERE total > " + minTotal);

// js_weak_crypto: broken hash
const digest = crypto.createHash("md5").update(password).digest("hex");

// js_implied_eval: string instead of a function
setTimeout("refreshData()", 1000);

module.exports = { result, adder };
