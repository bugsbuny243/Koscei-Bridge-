package handlers

// APICodeConflict is used when an immutable stored object exists but fails its
// canonical integrity contract. It is intentionally distinct from user input.
const APICodeConflict = "CONFLICT"
