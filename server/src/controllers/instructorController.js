import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Only safe, non-secret fields are ever sent back.
function publicProfile(doc) {
  return {
    name: doc.name,
    username: doc.username,   // not secret; the dashboard shows "@username"
    department: doc.department,
    role: doc.role
  };
}

// ---------- validation rules + a clear message for each way they can fail ----------
// {#label} is replaced by the field name (username, password, name, ...).

// username + password must be STRINGS. An object such as {"$ne": null}
// fails Joi.string() and is rejected before it can reach MongoDB.
const loginSchema = Joi.object({
  username: Joi.string().trim().max(50).required().messages({
    'any.required': 'Username is required.',
    'string.base':  'Username must be plain text (objects, numbers and arrays are not allowed).',
    'string.empty': 'Username cannot be empty.',
    'string.max':   'Username must be at most {#limit} characters long.'
  }),
  password: Joi.string().max(100).required().messages({
    'any.required': 'Password is required.',
    'string.base':  'Password must be plain text (objects, numbers and arrays are not allowed).',
    'string.empty': 'Password cannot be empty.',
    'string.max':   'Password must be at most {#limit} characters long.'
  })
}).messages({
  'object.base':    'The request body must be a JSON object with "username" and "password".',
  'object.unknown': 'Unexpected field "{#label}". Only "username" and "password" are allowed.'
});

// Only `name` may be searched, and it must be one piece of text.
// Any other key (role[$ne], $where, ...) is rejected.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(60).required().messages({
    'any.required': 'Please give a name to search for, e.g. ?name=Smith',
    'string.base':  'The search name must be a single piece of text.',
    'string.empty': 'The search name cannot be empty.',
    'string.max':   'The search name must be at most {#limit} characters long.'
  })
}).messages({
  'object.unknown': 'Search option "{#label}" is not allowed. You can only search by "name".'
});

// Validates `data` and returns the error message, or null if everything is fine.
// abortEarly: false     -> collect ALL problems, not just the first one.
// errors.wrap.label     -> show field names without extra quotes.
// A forbidden field (like role[$ne] or $where) is the most important problem,
// so its message is shown first; otherwise the first problem found is shown.
function check(schema, data) {
  const { value, error } = schema.validate(data, {
    abortEarly: false,
    errors: { wrap: { label: false } }
  });
  if (!error) return { value, message: null };
  const unknownField = error.details.find((d) => d.type === 'object.unknown');
  return { value, message: (unknownField || error.details[0]).message };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, message } = check(loginSchema, req.body);
    if (message) {
      return res.status(400).json({ message });
    }

    // Look up by username ONLY - the password is never put in the query.
    // '+password' is needed because the model hides it (select: false).
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');

    // Deliberately the SAME message for "no such user" and "wrong password":
    // different messages would tell an attacker which usernames exist.
    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(value.password, instructor.password);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors  (unchanged)
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// Makes regex special characters normal text, so ".*" is matched literally.
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// GET /api/instructors/search?name=Smith
export async function searchInstructors(req, res, next) {
  try {
    const { value, message } = check(searchSchema, req.query);
    if (message) {
      return res.status(400).json({ message });
    }

    // We build the filter ourselves; req.query is never passed to find().
    // Case-insensitive partial match: "smith" finds "Prof. Alice Smith".
    const filter = { name: new RegExp(escapeRegex(value.name), 'i') };

    const instructors = await Instructor.find(filter)
      .select('name department role')   // never return secrets
      .lean();

    if (instructors.length === 0) {
      return res.json({ count: 0, instructors: [], message: `No instructors match "${value.name}".` });
    }
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}