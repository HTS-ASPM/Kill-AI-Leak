"use client";

import { formatDistanceToNow } from "date-fns";
import { clsx } from "clsx";
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
      <div className="flex items-center justify-center py-12 text-[#5a7184] text-sm">
        No events found
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-blue-100 text-left text-xs font-medium uppercase tracking-wider text-[#5a7184]">
            <th className="px-4 py-3">Time</th>
            <th className="px-4 py-3">Source</th>
            {!compact && <th className="px-4 py-3">Actor</th>}
            <th className="px-4 py-3">Target</th>
            <th className="px-4 py-3">Rule Triggered</th>
            <th className="px-4 py-3">Decision</th>
            <th className="px-4 py-3">Severity</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-blue-50">
          {events.map((event, idx) => {
            const topGuardrail = event.guardrails?.[0];
            const decision = event.content.blocked ? "blocked" : "allowed";

            return (
              <tr
                key={event.id}
                className={clsx(
                  "group cursor-pointer transition-colors hover:bg-blue-50/80",
                  idx % 2 === 1 ? "bg-blue-50/30" : "bg-white",
                )}
                onClick={() => onRowClick?.(event)}
              >
                <td className="whitespace-nowrap px-4 py-3 text-[#5a7184]">
                  <span title={event.timestamp}>
                    {formatDistanceToNow(new Date(event.timestamp), {
                      addSuffix: true,
                    })}
                  </span>
                </td>
                <td className="whitespace-nowrap px-4 py-3">
                  <span className="rounded bg-blue-50 px-1.5 py-0.5 font-mono text-xs text-blue-700">
                    {event.source}
                  </span>
                </td>
                {!compact && (
                  <td className="whitespace-nowrap px-4 py-3 text-[#1a2b3c]">
                    <div className="flex flex-col">
                      <span className="font-medium">
                        {event.actor.name || event.actor.id}
                      </span>
                      {event.actor.namespace && (
                        <span className="text-xs text-[#5a7184]">
                          {event.actor.namespace}
                        </span>
                      )}
                    </div>
                  </td>
                )}
                <td className="whitespace-nowrap px-4 py-3 text-[#1a2b3c]">
                  <div className="flex flex-col">
                    <span>{event.target.provider || event.target.id}</span>
                    {event.target.model && (
                      <span className="text-xs text-[#5a7184]">
                        {event.target.model}
                      </span>
                    )}
                  </div>
                </td>
                <td className="whitespace-nowrap px-4 py-3 text-[#5a7184]">
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
