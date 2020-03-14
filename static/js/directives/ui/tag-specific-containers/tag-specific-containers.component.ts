import { Input, Component } from 'ng-metadata/core';

/**
 * A component that displays how long ago an event occurred, with associated
 * tooltip showing the actual time.
 */
@Component({
  selector: 'tagSpecificContainers',
  templateUrl: '/static/js/directives/ui/tag-specific-containers/tag-specific-containers.component.html'
})
export class TagSpecificContainers {
  @Input('<') public containers: any[];
  @Input('<') public loading: boolean;
}
