import { useState } from "react";
import { setToken } from "../api";

interface Props {
  rejected: boolean;
  onDone: () => void;
}

/** Asks for the API token; it is kept for this tab only. */
export function TokenPrompt({ rejected, onDone }: Props) {
  const [value, setValue] = useState("");
  return (
    <form
      className="token"
      onSubmit={(submit) => {
        submit.preventDefault();
        setToken(value.trim());
        onDone();
      }}
    >
      <h2>Token needed</h2>
      <p>
        {rejected
          ? "That token was not accepted."
          : "This Goliath asks for a token. It is kept for this tab only."}
      </p>
      <input
        type="password"
        aria-label="Token"
        autoComplete="off"
        value={value}
        onChange={(change) => setValue(change.target.value)}
      />
      <button type="submit" disabled={value.trim() === ""}>
        Continue
      </button>
    </form>
  );
}
