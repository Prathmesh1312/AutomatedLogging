import random
import logging
from typing import Dict, Any, List

logger = logging.getLogger("BSES.StateMachine")

class StateMachine:
    def __init__(self, persona: str, markov_table: Dict[str, Any]):
        self.persona = persona
        self.initial_state = markov_table.get("initial_state", "LOGGED_OUT")
        self.transitions = markov_table.get("transitions", {})
        
        # Validate that the model is well-defined
        self._validate_transitions()

    def _validate_transitions(self):
        """Checks for empty or malformed probability tables."""
        if not self.transitions:
            logger.warning(f"Persona '{self.persona}' initialized with empty transition map.")
            return

        for state, targets in list(self.transitions.items()):
            if not targets:
                logger.warning(f"State '{state}' in persona '{self.persona}' has no target transitions.")
                continue
            
            # Ensure probabilities are positive numbers
            total_prob = sum(targets.values())
            if abs(total_prob - 1.0) > 0.01:
                # Normalize probabilities if they don't sum to 1.0 due to rounding
                logger.debug(f"Normalizing transition probabilities for state '{state}' (sum={total_prob})")
                factor = 1.0 / total_prob
                self.transitions[state] = {k: v * factor for k, v in targets.items()}

    def get_next_state(self, current_state: str) -> str:
        """
        Draws the next state given the current state.
        If current_state is unknown or dead-end, resets to initial_state.
        """
        if current_state not in self.transitions or not self.transitions[current_state]:
            logger.debug(f"Current state '{current_state}' not defined or has no exits. Resetting to '{self.initial_state}'")
            return self.initial_state

        choices_dict = self.transitions[current_state]
        states: List[str] = list(choices_dict.keys())
        weights: List[float] = list(choices_dict.values())
        
        # High performance random choices select
        next_state = random.choices(states, weights=weights, k=1)[0]
        return next_state
