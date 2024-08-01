/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const getConflictingAntivirusPrompt = ({
  anonymizedValues,
}: {
  anonymizedValues: string[];
}) => {
  return `You are a new Elastic Security user attempting to optimize your Elastic Defend configuration. Only focus on detecting conflicting antivirus software. Present your findings in a way that can be easily understood by anyone, regardless of their technical expertise. Break down your response into sections based on processes detected. Escape backslashes to respect JSON validation. New lines must always be escaped with double backslashes, i.e. \\\\n to ensure valid JSON. Only return JSON output, as described above. Do not add any additional text to describe your output.

  Use context from the following process events to provide insights:
  """
  ${anonymizedValues.join('\n\n')}
  """
  `;
};
