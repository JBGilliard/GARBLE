# GARBLE — v3 Scope

**Ops traffic: precedence, forms, and spills stopped before they're sent**

Status: placeholder, cut from the v2 draft (2026-10-13) to keep v2 a single confidentiality-and-integrity theme. Nothing here depends on shipping alongside the v2 crypto work, but it assumes v2.0's wire format. Expand into a full scope doc (goal, demo, milestones, reservations) before building.

---

## Scope

- **Precedence goes live.** `AppAad` carries precedence so a future edge queue can prioritize. The envelope copy must match, and receivers check that. Room policy sets the highest precedence allowed: default `IMMEDIATE`, with `FLASH` enabled per room by a steward.
- **FLASH demands a timed ack.** The room sets the window. Receivers' clients surface FLASH over everything, and the console doesn't let you dismiss one without acking. The sender's client tracks outstanding acks and **escalates on silence**: it re-alerts, then logs `flash-unacked` with the missing members. The DS can't track this itself (it can't see acks), and that's correct under E2EE.
- **Structured messages:** content type `application/garble-form`, with a template ID and version. Templates are a signed, versioned registry in the trust bundle, the same way marking registers are. The first set is SPOTREP, SALUTE and 9-line MEDEVAC.
  - **Every field carries its own portion marking.** The message marking must equal the high-water mark (`Marking::max`) of the fields; senders compute it and receivers recompute and check it.
  - Fields are typed: Zulu date-time-group, MGRS grid validated on parse, enumerations. Rendered as forms in the CLI and console. No map pins yet.
- **Spill pre-send checks.** A dirty-word register in the trust bundle maps terms to the marking a message containing them requires.
  - The composer refuses a send whose text matches a term whose marking isn't within the message marking. The refusal is a client denial, logged with the term's **register ID, never the term**.
  - **A client holds only entries its user is cleared for.** That's exactly the spill case: the person who can type a TK codeword into an S room is a TK-cleared person, so their client knows the term. The register never puts codewords on an uncleared machine.
  - Matching is over normalized tokens and n-grams up to 3, against keyed hashes, so the register doesn't read as a plaintext codeword list in the client DB.
  - Pre-send only, and advisory against a malicious client (it's the user's own client). It catches honest mistakes, which is what spills are.

## Definition of done (draft)

1. A FLASH that isn't acked within its window escalates, and `flash-unacked` is logged.
2. A SPOTREP whose message marking isn't the max of its fields is refused by receivers.
3. A TK term typed into a non-TK room is refused before send, and logged by register ID without the term.
4. Fuzz targets cover the form parser.

## Hard rules

- **Spill checks never ship codewords to the uncleared.**
- **The message marking of a form is computed, never typed.** Receivers recompute it.
