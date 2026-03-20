"use client";

import { formatDistanceToNow } from "date-fns";
import SeverityBadge from "./SeverityBadge";
import StatusBadge from "./StatusBadge";
import type { Event } from "@/lib/types";

interface EventTableProps {
  events: Event[];
  compact?: boolean;
  onRowClick?: (event: Event) => void;
}

export default function EventTable({
  events,
  compact = false,
  onRowClick,
}: EventTableProps) {
  if (events.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
        No events found
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-300 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
            <th className="px-4 py-3">Time</th>
            <th className="px-4 py-3">Source</th>
            {!compact && <th className="px-4 py-3">Actor</th>}
            <th className="px-4 py-3">Target</th>
            <th className="px-4 py-3">Rule Triggered</th>
            <th className="px-4 py-3">Decision</th>
            <th className="px-4 py-3">Severity</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-300">
          {events.map((event) => {
            const topGuardrail = event.guardrails?.[0];
            const decision = event.content.blocked ? "blocked" : "allowed";

            return (
              <tr
                key={event.id}
                className="group cursor-pointer transition-colors hover:bg-surface-200/60"
                onClick={() => onRowClick?.(event)}
              >
                <td className="whitespace-nowrap px-4 py-3 text-gray-400">
                  <span title={event.timestamp}>
                    {formatDistanceToNow(new Date(event.timestamp), {
                      addSuffix: true,
                    })}
                  </span>
                </td>
                <td className="whitespace-nowrap px-4 py-3">
                  <span className="rounded bg-surface-300 px-1.5 py-0.5 font-mono text-xs text-gray-300">
                    {event.source}
                  </span>
                </td>
                {!compact && (
                  <td className="whitespace-nowrap px-4 py-3 text-gray-300">
                    <div className="flex flex-col">
                      <span className="font-medium">
                        {event.actor.name || event.actor.id}
                      </span>
                      {event.actor.namespace && (
                        <span className="text-xs text-gray-500">
                          {event.actor.namespace}
                        </span>
                      )}
                    </div>
                  </td>
                )}
                <td className="whitespace-nowrap px-4 py-3 text-gray-300">
                  <div className="flex flex-col">
                    <span>{event.target.provider || event.target.id}</span>
                    {event.target.model && (
                      <span className="text-xs text-gray-500">
                        {event.target.model}
                      </span>
                    )}
                  </div>
                </td>
                <td className="whitespace-nowrap px-4 py-3 text-gray-400">
                  {topGuardrail?.rule_name ?? "-"}
                </td>
                <td className="whitespace-nowrap px-4 py-3">
                  <StatusBadge status={decision} />
                </td>
                <td className="whitespace-nowrap px-4 py-3">
                  <SeverityBadge severity={event.severity} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
